"""Versioned JSON schemas (draft 2020-12) of the tool arguments: transport values only, never XAX source."""

from __future__ import annotations

SCHEMA_VERSION = "xax-mcp-tools-v1"

_HANDLE = {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[A-Za-z0-9_.@-]+$"}
_GEN = {"type": "integer", "minimum": 0, "maximum": 2 ** 31}
_CID = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": 256}
_CONT = {"type": "integer", "minimum": 0, "maximum": 2 ** 31}
_INT_TYPE = {"enum": ["b8", "b16", "b32", "b64"]}
_SMALL = {"type": "integer", "minimum": 0, "maximum": 4096}
_INT64 = {"type": "integer", "minimum": -(2 ** 64) + 1, "maximum": 2 ** 64 - 1}
_TOKEN = {"type": "string", "maxLength": 64, "pattern": "^[A-Za-z@][A-Za-z0-9.@_-]*$"}
EFFECTS = ["stdio", "filesystem.read", "filesystem.write", "network", "process", "environment", "clock"]
MUTATION_OPS = ["set_constant", "set_operation", "replace_operand", "delete", "prune_dead", "move", "insert_constant",
                "set_edge", "set_type", "set_signature"]

_MUTATION = {
    "type": "object",
    "required": ["op"],
    "additionalProperties": False,
    "properties": {
        "op": {"enum": MUTATION_OPS},
        "node": _TOKEN, "anchor": _TOKEN, "before": _TOKEN, "function": _TOKEN, "target": _TOKEN, "type": _TOKEN,
        "value": {"anyOf": [_INT64, _TOKEN]},
        "index": _SMALL, "id": _SMALL, "edge": _SMALL, "argument": _SMALL, "result": _SMALL,
        "params": {"type": "array", "maxItems": 64, "items": _TOKEN},
        "returns": {"type": "array", "maxItems": 64, "items": _TOKEN},
    },
}

TOOLS: dict[str, dict] = {
    "xax_capabilities": {
        "title": "XAX capabilities",
        "description": "Server/compiler identity, pinned XAX revision, targets, operations, carrier types, I/O modes, "
                       "granted rights, sandbox status and honest maturity labels. Call first.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    "xax_workspace": {
        "title": "XAX workspace",
        "description": "PROTOTYPE: describes the current store (the root bytes recorded in its header and its byte size). The "
                       "workspace handle lifecycle (open/list/describe/close) is not implemented by the native server yet; "
                       "the store is the host-granted seed until a transaction replaces it in the work directory. The server "
                       "does not re-verify the store; the compiler verifies it on build.",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    "xax_query": {
        "title": "XAX bounded query",
        "description": "PROTOTYPE: implements the root query only: the root bytes recorded in the current store's header and "
                       "its byte size. The server does not re-verify the store (xax_build resolves it first). The bounded "
                       "graph queries (functions, function_nodes, function_view, operands, neighborhood, uses, callers, "
                       "callees, type, effects, effect_summary, entity, proof, diff, repair) are not implemented by the "
                       "native server yet.",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    "xax_construct": {
        "title": "XAX construct",
        "description": "UNIMPLEMENTED natively; calls fail closed with 'unsupported'. Target contract: construct and verify a "
                       "NEW XAX program from one xax-construct-v1 carrier (typed semantic graph: types, functions of blocks of "
                       "[operation, operands, result types, extra] nodes, package entries). The carrier is transport; the "
                       "verified canonical store becomes a workspace. Platforms: linux-x86_64, windows-x86_64 (executable on "
                       "a host of the same platform; see xax_capabilities targets).",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["request"], "properties": {
            "request": {"type": "object", "required": ["format", "platform", "functions", "package"], "properties": {
                "format": {"const": "xax-construct-v1"},
                "platform": {"enum": ["linux-x86_64", "windows-x86_64"]},
                "types": {"type": "object", "maxProperties": 256},
                "functions": {"type": "array", "minItems": 1, "maxItems": 256, "items": {"type": "object"}},
                "package": {"type": "object"},
            }},
        }},
    },
    "xax_transaction": {
        "title": "XAX transaction",
        "description": "PROTOTYPE: applies one XAXEDIT1 transaction carrier to the current store by driving the host-granted "
                       "native XAX compiler's 'edit' command. 'record' is the carrier as a lowercase/uppercase hex string; the "
                       "edited store replaces the work directory's current store and the result reports its new canonical root. "
                       "Typed mutations, expected generation/root, candidates and rollback are not implemented yet.",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["record"], "properties": {
            "record": {"type": "string", "pattern": "^[0-9A-Fa-f]+$", "minLength": 2, "maxLength": 2097152},
        }},
    },
    "xax_build": {
        "title": "XAX build",
        "description": "PROTOTYPE: resolves and builds the current store with the host-granted native XAX compiler ('resolve' "
                       "then 'build'), writing snapshot/artifact/provenance into the host-granted work directory. Returns the "
                       "canonical root, artifact byte count and the provenance object (byte count and hex). Artifact handles, "
                       "entry/package selection, digest reports and toolchain caching are not implemented yet.",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    "xax_execute": {
        "title": "XAX execute",
        "description": "PROTOTYPE: resolves and builds the current store, then runs that artifact inside the native OS sandbox "
                       "and returns exit_code, duration_ms, flags (bit 0 timeout, bit 2 output truncated) and the artifact's "
                       "stdout/stderr as hex. The sandbox is a capability-less Windows AppContainer inside a job object "
                       "(fixed limits: 5 s CPU, 256 MiB, one process, 10 s wall, 1 MiB per stream); it ships beside the server "
                       "as xax-mcp-sandbox.exe and is built from native/sandbox.py. Takes NO arguments yet: the artifact "
                       "handle, input/output layout, argv, effects and per-call limits fail closed rather than being ignored; "
                       "Linux namespaces and the xax-mcp-io-v1 framing are not implemented. Requires the host-granted "
                       "execute right.",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    "xax_result": {
        "title": "XAX result",
        "description": "UNIMPLEMENTED natively; calls fail closed with 'unsupported'. Target contract: fetch a bounded chunk of "
                       "a large result by opaque handle: execution stdout (res_), a workspace's canonical store bytes (ws_), or "
                       "a stored diagnostic (diag_). Never returns unbounded data.",
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["handle"], "properties": {
            "handle": _HANDLE, "offset": _CONT, "length": {"type": "integer", "minimum": 1, "maximum": 65536},
        }},
    },
}
