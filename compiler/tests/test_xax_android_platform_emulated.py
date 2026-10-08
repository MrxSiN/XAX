"""NDK/POSIX contract programs executed under Unicorn with stubbed imports (ADR-206).

Each program is verified, compiled to an Android arm64 shared object, and its
export is run by ``benchmarks.android_elf_emulator`` with the ELF's own import
slots pointed at recording stubs.  Emulated execution, not device evidence.
"""
from __future__ import annotations

import struct

from benchmarks.android_elf_emulator import HEAP, run_export
from benchmarks.bench_android_arm64 import _reader
from xax_android import AndroidExport, compile_android_shared, inspect_android_elf
from xax_android_platform import aaudio_api, media_codec_api, ndk_type_objects
from xax_compiler import (
    EffectDomain,
    Kind,
    Operation,
    Permission,
    android_arm64_shared_general_target,
    bits_type,
    effect_type,
    memory_effect_type,
    pointer_type,
    stack_owner_type,
    verify_store,
)
from xax_graph_builder import GraphBuilder
from xax_platform import posix_android_api, posix_async_api

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
DEVICE, MEMORY = effect_type(EffectDomain.DEVICE, 0), memory_effect_type()


def _shared(parameters, body, results, extra, symbol=b"probe"):
    graph = GraphBuilder()
    block = graph.block(*parameters)
    block.ret(*body(block))
    function = graph.function(tuple(parameters), tuple(results))
    objects = (*ndk_type_objects(), *graph.objects.values(), *extra, *parameters, *results)
    target_object = android_arm64_shared_general_target()
    reader = _reader((function,), objects, target_object)
    verify_store(reader)
    shared = compile_android_shared(reader, (AndroidExport(symbol, function.cid),), target_object=target_object)
    return shared.data


def _call(block, symbol, operands, results):
    out = block.op(Operation.CALL_FOREIGN, operands, results, entity=symbol)
    return out if isinstance(out, tuple) else (out,)


def test_codec_lifecycle_runs_in_order_with_the_returned_handle():
    api = media_codec_api()
    mime = pointer_type(B8, Permission.READ, 1, space=2)

    def body(block):
        name, dev = block.params
        codec, token, dev = _call(block, api.create_decoder_by_type, (name, dev), (api.codec, api.codec_token, DEVICE))
        _s, token, dev = _call(block, api.start, (codec, token, dev), (B32, api.codec_token, DEVICE))
        _s, token, dev = _call(block, api.stop, (codec, token, dev), (B32, api.codec_token, DEVICE))
        _s, dev = _call(block, api.delete, (codec, token, dev), (B32, DEVICE))
        return (dev,)

    elf = _shared((mime, DEVICE), body, (DEVICE,), api.symbols)
    assert inspect_android_elf(elf).needed == (b"libmediandk.so",)
    handlers = {b"AMediaCodec_createDecoderByType": lambda m: 0xC0DE0000, b"AMediaCodec_start": lambda m: 0,
                b"AMediaCodec_stop": lambda m: 0, b"AMediaCodec_delete": lambda m: 0}
    _x0, trace = run_export(elf, b"probe", (HEAP,), handlers, heap=b"video/avc\0")
    assert [(name, args[0]) for name, args in trace] == [
        (b"AMediaCodec_createDecoderByType", HEAP), (b"AMediaCodec_start", 0xC0DE0000),
        (b"AMediaCodec_stop", 0xC0DE0000), (b"AMediaCodec_delete", 0xC0DE0000),
    ]


def test_aaudio_output_stream_builds_writes_and_closes():
    api = aaudio_api()
    buffer = pointer_type(B8, Permission.READ, 1, space=2)
    cell = pointer_type(B64, Permission.READ_WRITE, 8)
    owner = stack_owner_type()

    def out_cell(block):
        pointer, cell_owner, effect = block.op(Operation.STACK_ALLOC, (), (cell, owner, MEMORY), attributes=(8, 8))
        effect = block.op1(Operation.STORE_BITS_LE, (pointer, block.const(B64, 0), effect), MEMORY, attributes=(8, 8))
        return pointer, cell_owner, effect

    def body(block):
        data, dev, mem = block.params
        b_cell, b_owner, b_eff = out_cell(block)
        _s, b_tok, dev, b_eff = _call(block, api.create_stream_builder, (b_cell, dev, b_eff), (B32, api.builder_token, DEVICE, MEMORY))
        builder, b_eff = block.op(Operation.LOAD_BITS_LE, (b_cell, b_eff), (B64, MEMORY), attributes=(8, 8))
        for setter, value in ((api.set_direction, 0), (api.set_sample_rate, 48000), (api.set_channel_count, 2), (api.set_format, 1)):
            b_tok, dev = _call(block, setter, (builder, block.const(B32, value), b_tok, dev), (api.builder_token, DEVICE))
        s_cell, s_owner, s_eff = out_cell(block)
        _s, b_tok, s_tok, dev, s_eff = _call(block, api.open_stream, (builder, s_cell, b_tok, dev, s_eff),
                                             (B32, api.builder_token, api.stream_token, DEVICE, MEMORY))
        stream, s_eff = block.op(Operation.LOAD_BITS_LE, (s_cell, s_eff), (B64, MEMORY), attributes=(8, 8))
        _s, dev = _call(block, api.builder_delete, (builder, b_tok, dev), (B32, DEVICE))
        _s, s_tok, dev = _call(block, api.request_start, (stream, s_tok, dev), (B32, api.stream_token, DEVICE))
        _n, s_tok, dev, mem = _call(block, api.transfer, (stream, data, block.const(B32, 240), block.const(B64, 10_000_000), s_tok, dev, mem),
                                    (B32, api.stream_token, DEVICE, MEMORY))
        _s, s_tok, dev = _call(block, api.request_stop, (stream, s_tok, dev), (B32, api.stream_token, DEVICE))
        _s, dev = _call(block, api.close, (stream, s_tok, dev), (B32, DEVICE))
        block.op(Operation.STACK_END, (s_owner, s_eff), ())
        block.op(Operation.STACK_END, (b_owner, b_eff), ())
        return (dev, mem)

    elf = _shared((buffer, DEVICE, MEMORY), body, (DEVICE, MEMORY), (*api.symbols, cell, owner))

    def create(machine):
        machine.write(machine.x(0), struct.pack("<Q", 0xB0B0))
        return 0

    def open_stream(machine):
        machine.write(machine.x(1), struct.pack("<Q", 0x5E5E))
        return 0

    handlers = {
        b"AAudio_createStreamBuilder": create, b"AAudioStreamBuilder_openStream": open_stream,
        b"AAudioStream_write": lambda m: m.x(2),
        **{name: (lambda m: 0) for name in (b"AAudioStreamBuilder_setDirection", b"AAudioStreamBuilder_setSampleRate",
                                             b"AAudioStreamBuilder_setChannelCount", b"AAudioStreamBuilder_setFormat",
                                             b"AAudioStreamBuilder_delete", b"AAudioStream_requestStart",
                                             b"AAudioStream_requestStop", b"AAudioStream_close")},
    }
    _x0, trace = run_export(elf, b"probe", (HEAP,), handlers)
    names = [name for name, _args in trace]
    assert names == [
        b"AAudio_createStreamBuilder", b"AAudioStreamBuilder_setDirection", b"AAudioStreamBuilder_setSampleRate",
        b"AAudioStreamBuilder_setChannelCount", b"AAudioStreamBuilder_setFormat", b"AAudioStreamBuilder_openStream",
        b"AAudioStreamBuilder_delete", b"AAudioStream_requestStart", b"AAudioStream_write", b"AAudioStream_requestStop",
        b"AAudioStream_close",
    ]
    calls = dict(trace)
    assert calls[b"AAudioStreamBuilder_setSampleRate"][:2] == (0xB0B0, 48000)
    assert calls[b"AAudioStreamBuilder_openStream"][0] == 0xB0B0
    assert calls[b"AAudioStream_write"][:4] == (0x5E5E, HEAP, 240, 10_000_000)
    assert calls[b"AAudioStream_close"][0] == 0x5E5E


def test_owned_socket_is_created_and_closed_with_the_same_descriptor():
    base = posix_android_api()
    api = posix_async_api(base)
    net = base.network_effect

    def body(block):
        (effect,) = block.params
        fd, token, effect = _call(block, api.socket, (block.const(B32, 2), block.const(B32, 1 | 0o4000), block.const(B32, 0), effect),
                                  (B32, api.descriptor, net))
        _s, effect = _call(block, api.shutdown, (fd, block.const(B32, 2), effect), (B32, net))
        _s, effect = _call(block, api.close_socket, (fd, token, effect), (B32, net))
        return (effect,)

    elf = _shared((net,), body, (net,), (*api.symbols, api.descriptor))
    assert inspect_android_elf(elf).needed == (b"libc.so",)
    _x0, trace = run_export(elf, b"probe", (), {b"socket": lambda m: 9, b"shutdown": lambda m: 0, b"close": lambda m: 0})
    assert [name for name, _args in trace] == [b"socket", b"shutdown", b"close"]
    assert trace[0][1][:3] == (2, 1 | 0o4000, 0)
    assert trace[1][1][:2] == (9, 2) and trace[2][1][0] == 9
