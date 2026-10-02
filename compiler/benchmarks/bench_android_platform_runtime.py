"""Build the Android/AArch64 runtime probe for POSIX platform contracts.

The generated shared object contains only XAX-lowered calls.  The companion
``integration/android/validate_platform_contracts.sh`` C loader supplies raw
buffers/callbacks and checks file, pthread, and loopback-socket behavior on an
actual arm64 Android device or emulator.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from xax_android import AndroidExport, compile_android_shared, inspect_android_elf
from xax_compiler import (
    Block, Kind, Node, Operation, StoreReader, Terminator, ValueRef,
    android_arm64_shared_general_target, constant, function, graph_fragment,
    object_with_refs, write_store,
)
from xax_platform import posix_android_api

DIR = Path(__file__).parent
SHARED = DIR / "android_platform_runtime_probe.so"
EVIDENCE = DIR / "android_platform_runtime_probe_evidence.json"


def _reader_and_exports():
    api = posix_android_api()
    target = android_arm64_shared_general_target()
    zero = constant(api.b32, 0)
    open_flags = constant(api.b32, 0x241)  # O_WRONLY|O_CREAT|O_TRUNC on Android/Linux
    mode_0600 = constant(api.b32, 0o600)
    af_inet = constant(api.b32, 2)
    sock_stream = constant(api.b32, 1)

    file_params = (api.byte_ptr_read, api.byte_ptr_read, api.b64, api.byte_ptr_rw, api.filesystem_effect, api.memory_effect)
    file_nodes = (
        Node(Operation.CONSTANT, (), (api.b32,), entity=open_flags),
        Node(Operation.CONSTANT, (), (api.b32,), entity=mode_0600),
        Node(Operation.CONSTANT, (), (api.b32,), entity=zero),
        Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0), ValueRef.node_result(0, 1), ValueRef.parameter(0, 4)), (api.b32, api.filesystem_effect), entity=api.open),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 3, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 2), ValueRef.node_result(0, 3, 1)), (api.b64, api.filesystem_effect), entity=api.write),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 3, 0), ValueRef.node_result(0, 4, 1)), (api.b32, api.filesystem_effect), entity=api.close),
        Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 2), ValueRef.node_result(0, 2), ValueRef.node_result(0, 5, 1)), (api.b32, api.filesystem_effect), entity=api.open),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 6, 0), ValueRef.parameter(0, 3), ValueRef.parameter(0, 2), ValueRef.node_result(0, 6, 1), ValueRef.parameter(0, 5)), (api.b64, api.filesystem_effect, api.memory_effect), entity=api.read),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 6, 0), ValueRef.node_result(0, 7, 1)), (api.b32, api.filesystem_effect), entity=api.close),
    )
    file_graph = graph_fragment([Block(file_params, file_nodes, Terminator.return_((ValueRef.node_result(0, 7, 0), ValueRef.node_result(0, 8, 1), ValueRef.node_result(0, 7, 2))))])
    file_fn = function(file_graph, file_params, (api.b64, api.filesystem_effect, api.memory_effect))

    create_params = (api.byte_ptr_rw, api.byte_ptr_read, api.function_ptr, api.byte_ptr_rw, api.thread_effect, api.memory_effect)
    create_nodes = (
        Node(Operation.CALL_FOREIGN, tuple(ValueRef.parameter(0, i) for i in range(6)), (api.b32, api.thread_effect, api.memory_effect), entity=api.pthread_create),
    )
    create_graph = graph_fragment([Block(create_params, create_nodes, Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2))))])
    create_fn = function(create_graph, create_params, (api.b32, api.thread_effect, api.memory_effect))

    join_params = (api.b64, api.byte_ptr_rw, api.thread_effect, api.memory_effect)
    join_nodes = (
        Node(Operation.CALL_FOREIGN, tuple(ValueRef.parameter(0, i) for i in range(4)), (api.b32, api.thread_effect, api.memory_effect), entity=api.pthread_join),
    )
    join_graph = graph_fragment([Block(join_params, join_nodes, Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2))))])
    join_fn = function(join_graph, join_params, (api.b32, api.thread_effect, api.memory_effect))

    socket_params = (
        api.byte_ptr_read, api.b32, api.byte_ptr_read, api.b64, api.byte_ptr_rw, api.b64,
        api.network_effect, api.filesystem_effect, api.memory_effect,
    )
    socket_nodes = (
        Node(Operation.CONSTANT, (), (api.b32,), entity=af_inet),
        Node(Operation.CONSTANT, (), (api.b32,), entity=sock_stream),
        Node(Operation.CONSTANT, (), (api.b32,), entity=zero),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1), ValueRef.node_result(0, 2), ValueRef.parameter(0, 6)), (api.b32, api.network_effect), entity=api.socket),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 3, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 3, 1)), (api.b32, api.network_effect), entity=api.connect),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 3, 0), ValueRef.parameter(0, 2), ValueRef.parameter(0, 3), ValueRef.node_result(0, 2), ValueRef.node_result(0, 4, 1)), (api.b64, api.network_effect), entity=api.send),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 3, 0), ValueRef.parameter(0, 4), ValueRef.parameter(0, 5), ValueRef.node_result(0, 2), ValueRef.node_result(0, 5, 1), ValueRef.parameter(0, 8)), (api.b64, api.network_effect, api.memory_effect), entity=api.recv),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 3, 0), ValueRef.parameter(0, 7)), (api.b32, api.filesystem_effect), entity=api.close),
    )
    socket_returns = (api.b64, api.network_effect, api.filesystem_effect, api.memory_effect)
    socket_graph = graph_fragment([Block(socket_params, socket_nodes, Terminator.return_((ValueRef.node_result(0, 6, 0), ValueRef.node_result(0, 6, 1), ValueRef.node_result(0, 7, 1), ValueRef.node_result(0, 6, 2))))])
    socket_fn = function(socket_graph, socket_params, socket_returns)

    functions = (file_fn, create_fn, join_fn, socket_fn)
    declarations = tuple(dict.fromkeys((*api.types, *api.symbols, zero, open_flags, mode_0600, af_inet, sock_stream, target, *functions)))
    module = object_with_refs(Kind.MODULE, declarations)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [
        *api.types, *api.symbols, zero, open_flags, mode_0600, af_inet, sock_stream, target,
        file_graph, file_fn, create_graph, create_fn, join_graph, join_fn, socket_graph, socket_fn,
        module, root,
    ]
    reader = StoreReader(write_store(root.cid, objects))
    exports = (
        AndroidExport(b"xax_file_probe", file_fn.cid),
        AndroidExport(b"xax_thread_create_probe", create_fn.cid),
        AndroidExport(b"xax_thread_join_probe", join_fn.cid),
        AndroidExport(b"xax_socket_probe", socket_fn.cid),
    )
    return reader, target, exports


def build_probe(*, packed: bool = False) -> bytes:
    """The probe library; ``packed`` binds the same program to the packed container (format 5, ADR-105)."""
    reader, target, exports = _reader_and_exports()
    if packed:
        target = android_arm64_shared_general_target(packed=True)
    return compile_android_shared(reader, exports, target_object=target, soname=b"libxax_platform_probe.so").data


def collect_evidence(runtime: dict[str, object] | None = None) -> dict[str, object]:
    shared = build_probe()
    view = inspect_android_elf(shared)
    evidence: dict[str, object] = {
        "schema": "xax-android-platform-runtime-proof-v1",
        "target": "android-arm64-v8a-shared-v4",
        "artifact_bytes": len(shared),
        "artifact_sha256": hashlib.sha256(shared).hexdigest(),
        "exports": ["xax_file_probe", "xax_thread_create_probe", "xax_thread_join_probe", "xax_socket_probe"],
        "imports": sorted(name.decode("ascii") for name in view.imports),
        "contracts": ["file.open/write/read/close", "pthread.create/join", "socket/connect/send/recv/close"],
        "runtime": runtime or {"executed": False, "reason": "requires adb plus a compatible arm64 Android device/emulator"},
    }
    return evidence


def main() -> None:
    shared = build_probe()
    SHARED.write_bytes(shared)
    evidence = collect_evidence()
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(SHARED)
    print(EVIDENCE)


if __name__ == "__main__":
    main()
