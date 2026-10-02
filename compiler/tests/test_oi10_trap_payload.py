import json

import pytest

from xax_aarch64 import compile_aarch64
from xax_compiler import (
    Block,
    Kind,
    SemanticObject,
    StoreReader,
    Terminator,
    TrapReason,
    XaxError,
    XaxTrap,
    aarch64_baremetal_target,
    decode_trap_payload,
    execute,
    function,
    graph_fragment,
    object_with_refs,
    trap_diagnostic_json,
    trap_payload,
    verify_store,
    write_store,
    x86_64_windows_target,
)
from xax_x86_64 import compile_native


def _fixture(target, reason=0x1234, target_data=b"platform-reason"):
    graph = graph_fragment([Block((), (), Terminator.trap(trap_payload(reason, target_data)))])
    fn = function(graph, (), ())
    module = object_with_refs(Kind.MODULE, [fn, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    reader = StoreReader(write_store(root.cid, [graph, fn, target, module, root]))
    return reader, graph, fn


def _a64_words(code):
    return tuple(int.from_bytes(code[i : i + 4], "little") for i in range(0, len(code), 4))


def test_payload_core_round_trips_and_empty_is_unspecified():
    assert trap_payload(TrapReason.UNSPECIFIED) == b""
    assert decode_trap_payload(b"") == (0, b"")
    payload = trap_payload(0x1234, b"\xaa\xbb")
    assert decode_trap_payload(payload) == (0x1234, b"\xaa\xbb")
    assert payload == b"\xb4\x24\xaa\xbb"


def test_payload_rejects_noncanonical_or_out_of_range_reason():
    with pytest.raises(ValueError, match="zero trap reason"):
        decode_trap_payload(b"\x00")
    with pytest.raises(ValueError, match="unterminated|oversized"):
        decode_trap_payload(b"\x80")
    with pytest.raises(ValueError, match="16 bits"):
        trap_payload(0x10000)


def test_verifier_rejects_malformed_payload_deterministically():
    valid = graph_fragment([Block((), (), Terminator.trap(trap_payload(1)))])
    assert valid.body.endswith(b"\x01\x01")
    bad_graph = SemanticObject.create(Kind.GRAPH_FRAGMENT, valid.body[:-1] + b"\x80", valid.references)
    fn = function(bad_graph, (), ())
    module = object_with_refs(Kind.MODULE, [fn])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    reader = StoreReader(write_store(root.cid, [bad_graph, fn, module, root]))
    for _ in range(2):
        with pytest.raises(XaxError) as caught:
            verify_store(reader)
        assert caught.value.diagnostic.code == "XAX.CONTROL.TRAP_PAYLOAD"
        assert caught.value.diagnostic.rule == "TRAP-PAYLOAD-CANONICAL"


def test_interpreter_and_diagnostic_expose_portable_reason_and_target_suffix():
    target = x86_64_windows_target()
    reader, _graph, fn = _fixture(target, 0x1234, b"x86-detail")
    with pytest.raises(XaxTrap) as caught:
        execute(reader, fn.cid, ())
    trap = caught.value
    assert trap.reason == 0x1234
    assert trap.target_data == b"x86-detail"
    diagnostic = json.loads(trap_diagnostic_json(trap))
    assert diagnostic == {
        "trap": {
            "payload": trap_payload(0x1234, b"x86-detail").hex(),
            "reason": 0x1234,
            "target_data": b"x86-detail".hex(),
        }
    }


def test_x86_64_native_trap_places_reason_in_rax_then_ud2():
    target = x86_64_windows_target()
    reader, _graph, fn = _fixture(target, 0x1234, b"windows-exception-detail")
    image = compile_native(reader, fn.cid, target.cid)
    # mov rax, 0x1234 ; ud2. Existing x86 bootstrap may have a frame prefix.
    assert image.code.endswith(bytes.fromhex("48b834120000000000000f0b"))


def test_aarch64_native_trap_places_reason_in_x0_and_brk_immediate():
    target = aarch64_baremetal_target()
    reader, _graph, fn = _fixture(target, 0x1234, b"firmware-detail")
    image = compile_aarch64(reader, fn.cid, target.cid)
    words = _a64_words(image.code)
    assert len(words) == 2
    assert words[0] == 0xD2824680  # movz x0, #0x1234
    assert words[1] == 0xD4200000 | (0x1234 << 5)  # brk #0x1234


def test_target_specific_suffix_changes_semantic_identity_not_portable_native_mapping():
    for target, compiler in ((x86_64_windows_target(), compile_native), (aarch64_baremetal_target(), compile_aarch64)):
        reader_a, graph_a, fn_a = _fixture(target, 7, b"detail-a")
        reader_b, graph_b, fn_b = _fixture(target, 7, b"detail-b")
        reader_c, _graph_c, fn_c = _fixture(target, 8, b"detail-a")
        assert graph_a.cid != graph_b.cid
        assert compiler(reader_a, fn_a.cid, target.cid).code == compiler(reader_b, fn_b.cid, target.cid).code
        assert compiler(reader_a, fn_a.cid, target.cid).code != compiler(reader_c, fn_c.cid, target.cid).code


def test_same_payload_is_deterministic_canonical_identity():
    target = aarch64_baremetal_target()
    _reader_a, graph_a, _fn_a = _fixture(target, 17, b"same")
    _reader_b, graph_b, _fn_b = _fixture(target, 17, b"same")
    assert graph_a.cid == graph_b.cid

def test_committed_evidence_reproduces():
    from benchmarks.bench_oi10_trap_payload import build
    from pathlib import Path
    committed = json.loads((Path(__file__).parents[1] / "benchmarks" / "oi10_trap_payload_evidence.json").read_text())
    assert build() == committed
