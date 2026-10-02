import platform

import pytest

import blake3 as blake3_module
from xax_compiler import Operation, decode_native_target, execute
from xax_native_blake3 import (
    build_blake3_compress_program,
    compile_blake3_compress_native,
    load_blake3_compress_program,
    native_blake3_compressor,
)


IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)


def _args():
    cv = tuple((word ^ (index * 0x01010101)) & 0xFFFFFFFF for index, word in enumerate(IV))
    block = tuple((index * 0x9E3779B1 + 0x1234567) & 0xFFFFFFFF for index in range(16))
    counter = 0x123456789ABCDEF0
    return cv, block, counter, 63, 0x0B



def test_committed_blake3_xax_store_matches_regenerated_graph_byte_for_byte():
    from xax_compiler import write_store
    from xax_native_blake3_store import STORE_BYTES

    generated = build_blake3_compress_program()
    regenerated = write_store(generated.reader.root_cid, generated.reader.objects())
    assert regenerated == STORE_BYTES
    loaded = load_blake3_compress_program()
    assert loaded.function.cid == generated.function.cid
    assert loaded.graph.cid == generated.graph.cid
    assert loaded.target.cid == generated.target.cid

def test_blake3_compress_is_an_ordinary_verified_xax_graph():
    program = build_blake3_compress_program()
    graph = program.reader.get(program.graph.cid)
    assert graph.cid == program.graph.cid

    cv, block, counter, block_len, flags = _args()
    expected = blake3_module._compress_python(cv, block, counter, block_len, flags)
    arguments = (*cv, *block, counter & 0xFFFFFFFF, counter >> 32, block_len, flags)
    (actual,) = execute(program.reader, program.function.cid, arguments)
    assert actual == expected


def test_blake3_graph_uses_xor_rotate_and_normal_native_compile_path():
    program = build_blake3_compress_program()
    image = compile_blake3_compress_native(program)
    assert image.target_cid == program.target.cid
    assert image.parameter_widths == (32,) * 28
    assert image.return_kinds == ("a64",)
    assert len(image.code) > 1000

    # Native semantic ranges prove that the ordinary compiler emitted machine
    # code for the graph nodes rather than substituting a handwritten hash leaf.
    assert len(image.semantic_ranges) > 700
    supported = decode_native_target(program.target).supported_operations
    assert Operation.BIT_XOR in supported
    assert Operation.ROTATE_RIGHT in supported


@pytest.mark.skipif(platform.machine().lower() not in ("x86_64", "amd64"), reason="native x86-64 execution proof")
def test_blake3_xax_graph_runs_natively_and_matches_python_leaf():
    native = native_blake3_compressor()
    cv, block, counter, block_len, flags = _args()
    expected = blake3_module._compress_python(cv, block, counter, block_len, flags)
    assert native.compress(cv, block, counter, block_len, flags) == expected


def test_public_blake3_digest_matches_bootstrap_leaf_with_native_acceleration():
    payload = bytes(range(256)) * 20
    accelerated = blake3_module.blake3(payload).digest()

    native = blake3_module._NATIVE_COMPRESSOR
    attempted = blake3_module._NATIVE_ATTEMPTED
    try:
        blake3_module._NATIVE_COMPRESSOR = None
        blake3_module._NATIVE_ATTEMPTED = True
        bootstrap = blake3_module.blake3(payload).digest()
    finally:
        blake3_module._NATIVE_COMPRESSOR = native
        blake3_module._NATIVE_ATTEMPTED = attempted
    assert accelerated == bootstrap
