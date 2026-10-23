"""The native XAX MCP server over its real STDIO transport, as a Windows x86-64 executable.

The executable is the PE32+ that XAX builds from the committed canonical store.  Set XAX_MCP_HOME to the
``MrxSiN/XAX-MCP`` checkout that holds the committed carriers and artifacts, or XAX_MCP_NATIVE_EXE to an already
built executable.  The authoritative programs are ``programs/*.xax`` in this directory; the tool schemas the
carrier embeds are ``programs/tool-schemas.json``.  Python is a test client here, never a server.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import queue
import random
import shutil
import subprocess
import sys
import threading
import types
from pathlib import Path

import pytest

TOOLING = Path(__file__).resolve().parents[1]


def _home() -> Path:
    """The ``MrxSiN/XAX-MCP`` checkout: committed carriers, stores and artifacts the tests compare against."""
    value = os.environ.get("XAX_MCP_HOME")
    if not value:
        pytest.skip("set XAX_MCP_HOME to the XAX-MCP checkout (committed carriers and artifacts)")
    return Path(value)


def _native() -> Path:
    return _home() / "native"
WINDOWS_X86_64 = sys.platform == "win32" and platform.machine().lower() in ("amd64", "x86_64")
pytestmark = pytest.mark.skipif(not WINDOWS_X86_64, reason="the native server is a windows-x86_64 PE32+ executable")
VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
TOOLS = ("xax_capabilities", "xax_workspace", "xax_query", "xax_construct", "xax_transaction", "xax_build",
         "xax_execute", "xax_result")
RIGHT_OF = {"xax_workspace": "read", "xax_query": "read", "xax_construct": "mutate", "xax_transaction": "mutate",
            "xax_build": "build", "xax_execute": "execute", "xax_result": "read"}
# Tools that drive the host-granted native compiler: without XAX_MCP_COMPILER/WORK/STORE they report denied_capability.
COMPILER_TOOLS = {"xax_workspace", "xax_query", "xax_transaction", "xax_build", "xax_execute"}
# Tools with a host grant of their own: without it they report denied_capability (construct: XAX_MCP_CONSTRUCT/WORK).
GATED_TOOLS = COMPILER_TOOLS | {"xax_construct"}
LMAX = 4 * 1024 * 1024


def _schemas():
    """The tool schemas the server carrier embeds, as transport data (not a Python module)."""
    document = json.loads((TOOLING / "programs" / "tool-schemas.json").read_text(encoding="utf-8"))
    return types.SimpleNamespace(SCHEMA_VERSION=document["version"],
                                 TOOLS={tool["name"]: {key: value for key, value in tool.items() if key != "name"}
                                        for tool in document["tools"]})


@pytest.fixture(scope="module")
def exe(tmp_path_factory) -> str:
    if os.environ.get("XAX_MCP_NATIVE_EXE"):
        return os.environ["XAX_MCP_NATIVE_EXE"]
    built = _native() / "xax-mcp-native.exe"
    if not built.is_file():
        pytest.skip("set XAX_MCP_NATIVE_EXE or commit native/xax-mcp-native.exe")
    return str(built)


class Server:
    """One native server process; ``exchange`` sends a line and waits for exactly one response line."""

    def __init__(self, exe: str, *args: str, env: dict | None = None):
        self.process = subprocess.Popen([exe, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env=dict(os.environ, **env) if env else None)
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def send(self, message) -> None:
        data = message if isinstance(message, bytes) else json.dumps(message, separators=(",", ":")).encode()
        self.process.stdin.write(data if data.endswith(b"\n") else data + b"\n")
        self.process.stdin.flush()

    def receive(self, timeout: float = 30) -> dict:
        line = self.lines.get(timeout=timeout)
        assert line is not None, "server closed stdout"
        return json.loads(line)

    def exchange(self, message, timeout: float = 30) -> dict:
        self.send(message)
        return self.receive(timeout)

    def request(self, method: str, params=None, id_=1) -> dict:
        message = {"jsonrpc": "2.0", "id": id_, "method": method}
        if params is not None:
            message["params"] = params
        return self.exchange(message)

    def call(self, name: str, arguments=None, id_=1) -> dict:
        params = {"name": name} if arguments is None else {"name": name, "arguments": arguments}
        result = self.request("tools/call", params, id_)["result"]
        payload = result["structuredContent"]
        assert json.loads(result["content"][0]["text"]) == payload and result["content"][0]["type"] == "text"
        assert result["isError"] == (not payload["ok"])
        return payload

    def close(self, timeout: float = 30):
        self.process.stdin.close()
        rest = []
        while (line := self.lines.get(timeout=timeout)) is not None:
            rest.append(line)
        code = self.process.wait(timeout)
        return code, rest, self.process.stderr.read()


@pytest.fixture
def server(exe):
    s = Server(exe)
    yield s
    if s.process.poll() is None:
        s.process.kill()


def test_initialize_negotiates_handshake_versions(server):
    for k, version in enumerate(VERSIONS):
        result = server.request("initialize", {"protocolVersion": version, "capabilities": {},
                                               "clientInfo": {"name": "t", "version": "0"}}, k)["result"]
        assert result["protocolVersion"] == version
    for params in ({"protocolVersion": "1999-01-01"}, {"protocolVersion": 7}, {}, None, [1]):
        result = server.request("initialize", params)["result"]
        assert result["protocolVersion"] == "2025-11-25", params
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"]["name"] == "xax-mcp" and result["serverInfo"]["version"].endswith("+native")
    assert "Call xax_capabilities first" in result["instructions"]
    assert server.close()[0] == 0


def test_ping_and_tools_list(server):
    assert server.request("ping", id_="p") == {"jsonrpc": "2.0", "id": "p", "result": {}}
    tools = server.request("tools/list")["result"]["tools"]
    schemas = _schemas()
    assert [tool["name"] for tool in tools] == list(TOOLS) == list(schemas.TOOLS)
    for tool in tools:
        spec = schemas.TOOLS[tool["name"]]
        assert (tool["title"], tool["description"], tool["inputSchema"], tool["annotations"]) == (
            spec["title"], spec["description"], spec["inputSchema"], spec["annotations"])
        assert tool["_meta"] == {"xax-mcp/schema": schemas.SCHEMA_VERSION}


def test_notifications_and_client_responses_get_no_reply(server):
    for message in ({"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
                    {"jsonrpc": "2.0", "method": "notifications/unknown"},
                    {"jsonrpc": "2.0", "id": 5, "result": {}},
                    {"jsonrpc": "2.0", "id": 6, "error": {"code": 1, "message": "x"}}):
        server.send(message)
    server.send(b"   \t ")  # blank lines are not messages
    assert server.request("ping", id_=9)["id"] == 9  # the next line is the ping's: nothing was answered before it
    code, rest, _ = server.close()
    assert (code, rest) == (0, [])


@pytest.mark.parametrize("line, code, has_id", [
    (b'{"jsonrpc":"2.0","id":4,"method":"nope"}', -32601, True),
    (b"not json", -32700, False),
    (b'{"jsonrpc":"2.0","id":1,"method":"ping"', -32700, False),
    (b"[1,2]", -32600, False),
    (b"42", -32600, False),
    (b'{"id":1,"method":"ping"}', -32600, True),
    (b'{"jsonrpc":"1.0","id":1,"method":"ping"}', -32600, True),
    (b'{"jsonrpc":2.0,"id":1,"method":"ping"}', -32600, True),
    (b'{"jsonrpc":"2.0","id":null,"method":"ping"}', -32600, False),
    (b'{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}', -32600, False),
    (b'{"jsonrpc":"2.0","id":1,"method":7}', -32600, True),
    (b'{"jsonrpc":"2.0","id":1}', -32600, True),
    (b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}', -32602, True),
    (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":3}}', -32602, True),
    (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xax_query","arguments":[1]}}', -32602, True),
])
def test_jsonrpc_errors(server, line, code, has_id):
    response = server.exchange(line)
    assert response["jsonrpc"] == "2.0" and response["error"]["code"] == code
    assert (response["id"] is not None) == has_id
    if code == -32601:
        assert response["error"]["data"] == "nope"
    assert server.request("ping", id_=2)["result"] == {}  # the stream stays usable


def test_ids_are_echoed_exactly(server):
    for raw in (b'"a\\"b\\u00e9\xc3\xa9"', b"18446744073709551621", b"-9223372036854775809", b"1.5e3", b"0", b'""'):
        response = server.exchange(b'{"jsonrpc":"2.0","method":"ping","id":' + raw + b"}")
        assert response["id"] == json.loads(raw.decode()) and response["result"] == {}


def test_tool_dispatch_under_default_rights(server):
    payload = server.call("xax_capabilities", {})
    assert payload["ok"] and payload["authority"]["rights"] == ["build", "mutate", "read"]
    assert payload["server"]["python_on_request_path"] is False
    assert server.call("xax_capabilities") == payload  # arguments may be omitted
    for tool in TOOLS[1:]:
        payload = server.call(tool, {})
        if tool == "xax_execute":
            assert payload["error"]["code"] == "denied_capability"
            assert payload["error"]["repair"] == ["the host owner may add --allow-execute to the server launch command"]
        elif tool == "xax_construct":
            assert payload["error"]["code"] == "denied_capability", (tool, payload)
            assert "XAX_MCP_CONSTRUCT" in payload["error"]["message"]
        elif tool in COMPILER_TOOLS:
            assert payload["error"]["code"] == "denied_capability", (tool, payload)
            assert "XAX_MCP_COMPILER" in payload["error"]["message"]
        else:
            assert payload["error"]["code"] == "unsupported" and tool in payload["error"]["message"]
    assert server.call("bogus", {})["error"] == {"code": "unsupported", "message": "unknown tool 'bogus'"}


def test_capabilities_rejects_properties(server):
    error = server.call("xax_capabilities", {"x": 1})["error"]
    assert error == {"code": "invalid_request", "details": {"errors": 1},
                     "message": "(root): Additional properties are not allowed ('x' was unexpected)"}
    error = server.call("xax_capabilities", {"a": 1, "b": {"c": [2]}})["error"]
    assert error["code"] == "invalid_request" and "2 properties were unexpected" in error["message"]


@pytest.mark.parametrize("args, rights", [
    ((), ["build", "mutate", "read"]),
    (("--allow-execute",), ["build", "execute", "mutate", "read"]),
    (("--read-only",), ["read"]),
    (("--read-only", "--allow-execute"), ["read"]),
    (("--deny", "read"), ["build", "mutate"]),
    (("--deny=build", "--allow-execute", "--deny", "mutate"), ["execute", "read"]),
    (("--no-warm-server", "--deny=read", "--deny=mutate", "--deny=build"), []),
])
def test_host_rights_come_from_launch_flags(exe, args, rights):
    server = Server(exe, *args)
    try:
        assert server.call("xax_capabilities", {})["authority"]["rights"] == rights
        for tool, right in RIGHT_OF.items():
            # a tool argument never grants a right
            error = server.call(tool, {"rights": ["execute"], "allow_execute": True})["error"]
            expected = ("unsupported" if right in rights and tool not in GATED_TOOLS else "denied_capability")
            assert error["code"] == expected, (tool, error)
    finally:
        server.process.kill()


@pytest.mark.parametrize("args", [("--grant", "read"), ("--wall-ms", "5"), ("--deny",), ("--deny", "everything"),
                                  ("--deny=exec",), ("--allow-execute-now",), ('--read-only"x',), ("-h",)])
def test_unknown_flags_fail_closed(exe, args):
    completed = subprocess.run([exe, *args], input=b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n', capture_output=True, timeout=30)
    assert completed.returncode == 2 and completed.stdout == b""
    assert b"unsupported command-line argument" in completed.stderr


def test_limits(server):
    huge = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"' + b"a" * LMAX + b'"}}'
    response = server.exchange(huge)
    assert response["id"] is None and response["error"]["code"] == -32600 and str(LMAX) in response["error"]["message"]
    assert server.request("ping", id_=2)["id"] == 2
    big = "a" * (1024 * 1024)
    error = server.call("xax_query", {"x": big})["error"]
    size = len(json.dumps({"x": big}, separators=(",", ":")))
    assert error == {"code": "resource_limit", "message": f"arguments are {size} bytes; the limit is 1048576"}
    for depth, ok in ((63, True), (64, False)):  # the envelope object is one level; 64 levels in all are accepted
        line = b'{"jsonrpc":"2.0","id":3,"method":"ping","params":' + b"[" * depth + b"]" * depth + b"}"
        assert ("result" in server.exchange(line)) == ok, depth


def test_framing(server):
    assert server.exchange(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\r\n')["id"] == 1  # CRLF clients
    for k in range(500):
        server.send({"jsonrpc": "2.0", "id": k, "method": "ping"})
    assert [server.receive()["id"] for _ in range(500)] == list(range(500))
    server.process.stdin.write(b'{"jsonrpc":"2.0","id":"last","method":"ping"}')  # no newline before EOF
    code, rest, stderr = server.close()
    assert code == 0 and [json.loads(line)["id"] for line in rest] == ["last"] and stderr == b""


def _random_json(rng: random.Random, depth: int = 0) -> bytes:
    ws = lambda: rng.choice([b"", b"", b" ", b"\t", b"\r", b" \t "])  # noqa: E731
    kind = rng.randrange(8 if depth < 12 else 5)
    if kind == 0:
        return rng.choice([b"true", b"false", b"null"])
    if kind == 1:
        number = rng.choice([b"0", b"-0", str(rng.randrange(10 ** rng.randrange(1, 25))).encode()])
        if rng.random() < 0.3:
            number += b"." + str(rng.randrange(1000)).encode()
        if rng.random() < 0.3:
            number += rng.choice([b"e", b"E"]) + rng.choice([b"", b"+", b"-"]) + str(rng.randrange(400)).encode()
        return number
    if kind in (2, 3, 4):
        parts = []
        for _ in range(rng.randrange(6)):
            choice = rng.randrange(6)
            if choice == 0:
                parts.append(rng.choice([b'\\"', b"\\\\", b"\\/", b"\\b", b"\\f", b"\\n", b"\\r", b"\\t"]))
            elif choice == 1:
                parts.append(b"\\u%04x" % rng.randrange(0x10000))
            elif choice == 2:
                parts.append(chr(rng.choice([rng.randrange(0x80, 0x800), rng.randrange(0x800, 0xD800),
                                             rng.randrange(0xE000, 0x10000), rng.randrange(0x10000, 0x110000)])).encode())
            else:
                parts.append(bytes(rng.choice(b"abcXYZ019 ~{}[]:,'")))
        return b'"' + b"".join(parts) + b'"'
    if kind == 5:
        return b"[" + ws() + (b"," + ws()).join(_random_json(rng, depth + 1) for _ in range(rng.randrange(4))) + ws() + b"]"
    members = [b'"' + rng.choice([b"id", b"name", b"k", b"method", b"\\u0069d"]) + b'"' + ws()
               + b":" + ws() + _random_json(rng, depth + 1) for _ in range(rng.randrange(4))]
    return b"{" + ws() + (b"," + ws()).join(members) + ws() + b"}"


def _python_accepts(line: bytes) -> bool:
    """Python's strict reading: UTF-8 (RFC 3629) and RFC 8259 JSON without the NaN/Infinity extensions."""
    def reject(constant):
        raise ValueError(constant)

    try:
        json.loads(line.decode("utf-8"), parse_constant=reject)
        return True
    except (UnicodeDecodeError, ValueError):
        return False


def test_json_validation_matches_python_strict_parser(server):
    """Randomized differential: the native validator accepts a line exactly when Python's strict parser does."""
    seed = int(os.environ.get("XAX_NATIVE_FUZZ_SEED", random.randrange(1 << 32)))
    rng = random.Random(seed)
    mutations = [b"\x00", b"\x1f", b"\x7f", b"\x80", b"\xc0", b"\xc2", b"\xe0", b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
                 b"\xf5", b"\xff", b'"', b"\\", b",", b"]", b"}", b"[", b"{", b":", b"-", b"+", b".", b"e", b"0",
                 b"\\u12", b"\\x", b"tru", b"nul", b"NaN", b"Infinity", b"\xef\xbb\xbf"]
    accepted = rejected = 0
    for trial in range(1500):
        value = _random_json(rng)
        if trial % 2:
            at = rng.randrange(len(value) + 1)
            cut = rng.randrange(3)
            value = value[:at] + rng.choice(mutations) + value[at + cut:]
        line = b'{"jsonrpc":"2.0","id":' + str(trial).encode() + b',"method":"ping","params":' + value + b"}"
        response = server.exchange(line)
        native = response.get("error", {}).get("code") != -32700
        assert native == _python_accepts(line), (seed, line)
        accepted += native
        rejected += not native
    assert accepted > 300 and rejected > 300, (accepted, rejected)


def test_concurrent_servers_are_independent(exe):
    servers = [Server(exe, *args) for args in ((), ("--read-only",), ("--allow-execute",))]
    try:
        rights = [s.call("xax_capabilities", {})["authority"]["rights"] for s in servers]
        assert rights == [["build", "mutate", "read"], ["read"], ["build", "execute", "mutate", "read"]]
    finally:
        for s in servers:
            s.process.kill()


def test_standard_sdk_client(exe):
    """The official MCP Python SDK client (``mcp.Client``) negotiates with the native server and calls its tools."""
    mcp = pytest.importorskip("mcp")
    anyio = pytest.importorskip("anyio")
    if not hasattr(mcp, "Client"):
        pytest.skip("needs the mcp 2.x SDK client")
    from mcp.client.stdio import StdioServerParameters

    async def run():
        async with mcp.Client(StdioServerParameters(command=exe, args=["--read-only"]), read_timeout_seconds=60) as client:
            listed = await client.list_tools()
            capabilities = await client.call_tool("xax_capabilities", {})
            denied = await client.call_tool("xax_construct", {"request": {}})
            return listed, capabilities, denied

    listed, capabilities, denied = anyio.run(run)
    assert [tool.name for tool in listed.tools] == list(TOOLS)
    assert capabilities.structured_content["authority"]["rights"] == ["read"] and not capabilities.is_error
    assert denied.is_error and denied.structured_content["error"]["code"] == "denied_capability"


def test_programs_are_the_committed_artifacts():
    """The XAX programs in this directory are the source of the artifacts XAX-MCP deploys."""
    pairs = {
        "xax-mcp-native.xax": "xax-mcp-native-gen0.xax",
        "xax-mcp-sandbox.xax": "xax-mcp-sandbox-gen0.xax",
        "xax-mcp-seed.xax": "xax-mcp-seed.xax",
        "xax-mcp-seed-snapshot.xax": "xax-mcp-seed-snapshot.xax",
        "construction_request.json": "construction_request.json",
        "sandbox_request.json": "sandbox_request.json",
    }
    for program, artifact in pairs.items():
        assert (TOOLING / "programs" / program).read_bytes() == (_native() / artifact).read_bytes(), program


def test_native_build_is_deterministic(tmp_path):
    """The committed store builds to the same PE on every native ``xaxc build``; no author runs."""
    compiler = os.environ.get("XAX_MCP_TEST_COMPILER")
    if not compiler:
        pytest.skip("set XAX_MCP_TEST_COMPILER (native xaxc) to rebuild the committed store")
    store = TOOLING / "programs" / "xax-mcp-native.xax"
    hashes = []
    for index in range(2):
        artifact, provenance = tmp_path / f"server-{index}.exe", tmp_path / f"server-{index}.prov"
        built = subprocess.run([compiler, "build", str(store), str(artifact), str(provenance)],
                               capture_output=True, timeout=900)
        assert built.returncode == 0, built.stderr.decode(errors="replace")
        hashes.append(hashlib.sha256(artifact.read_bytes()).hexdigest())
        assert artifact.stat().st_size == 359424
    assert hashes[0] == hashes[1]


def test_native_compiler_chain_over_stdio(exe, tmp_path):
    """End to end: the server drives the host-granted native compiler through query, build and one transaction.

    Gated on XAX_MCP_TEST_COMPILER, the native xaxc executable, and XAX_NATIVE_SRC, the pinned XAX compiler/src used to
    author the XAXEDIT1 carrier.  Nothing here runs inside the server: the server spawns the native compiler itself.
    """
    compiler = os.environ.get("XAX_MCP_TEST_COMPILER")
    source = os.environ.get("XAX_NATIVE_SRC")
    if not compiler or not source:
        pytest.skip("set XAX_MCP_TEST_COMPILER (native xaxc) and XAX_NATIVE_SRC (XAX compiler/src) to drive the native chain")
    seed = TOOLING / "programs" / "xax-mcp-seed.xax"
    assert seed.read_bytes() == (_native() / "xax-mcp-seed.xax").read_bytes()
    work = tmp_path / "work"
    work.mkdir()
    shutil.copy(seed, work / "current.xax")
    seed_bytes = seed.read_bytes()
    seed_root = seed_bytes[7:39].hex()
    spec = importlib.util.spec_from_file_location("native_test_chain", TOOLING / "chain.py")
    chain = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chain)
    # The executor must be installed beside the server executable (the server derives its own directory).
    launcher = Path(exe).parent / "xax-mcp-sandbox.exe"
    if not launcher.is_file():
        committed = _native() / "xax-mcp-sandbox.exe"
        if not committed.is_file():
            pytest.skip("the committed executor PE is not in XAX_MCP_HOME/native")
        shutil.copy(committed, launcher)
    server = Server(exe, "--allow-execute",
                    env={"XAX_MCP_COMPILER": compiler, "XAX_MCP_WORK": str(work), "XAX_MCP_STORE": str(seed)})
    try:
        assert server.call("xax_query", {}) == {"bytes": len(seed_bytes), "ok": True, "root": seed_root,
                                               "workspace": "ws_0"}
        built = server.call("xax_build", {})
        provenance = bytes.fromhex(built["provenance"]["hex"])
        assert built["ok"] and built["root"] == seed_root and built["artifact"]["bytes"] > 0
        assert built["provenance"]["bytes"] == len(provenance) and seed_root in built["provenance"]["hex"]
        record, old = chain.make_record(Path(source), work / "current.xax", 41)
        assert old == 40 and record.startswith(b"XAXEDIT1")
        applied = server.call("xax_transaction", {"record": record.hex()})
        current = (work / "current.xax").read_bytes()
        assert applied == {"generation": 1, "ok": True, "root": current[7:39].hex(), "workspace": "ws_0"}
        assert applied["root"] != seed_root
        assert server.call("xax_query", {})["root"] == applied["root"]
        # A later build reports the edited store: the transaction replaced the work directory's current store.
        assert server.call("xax_build", {})["root"] == applied["root"]
        # xax_execute rebuilds the current store and runs the artifact in the native OS sandbox; the edit made it exit 41.
        executed = server.call("xax_execute", {})
        assert executed["ok"] and executed["exit_code"] == 41, executed
        assert executed["flags"] == 0 and executed["stdout_bytes"] == 0 and executed["stderr_bytes"] == 0
        assert executed["duration_ms"] >= 0
        # The prototype takes no arguments: anything else fails closed instead of being ignored.
        error = server.call("xax_execute", {"artifact": "current"})["error"]
        assert error["code"] == "invalid_request" and "takes no arguments" in error["message"]
    finally:
        code, rest, err = server.close()
        assert code == 0 and not rest, (code, rest, err)


def test_native_construct_over_stdio(exe, tmp_path):
    """End to end: the server decodes an inline carrier with the host-granted native construct command.

    Gated on XAX_MCP_TEST_CONSTRUCT, the native ``construct`` executable (XAX's carrier decoder).  The carrier is the
    committed ``native/sandbox_request.json``; the store the decoder writes must equal the committed
    ``native/xax-mcp-sandbox-gen0.xax`` byte for byte, and it becomes the work directory's current store.  Nothing
    here decodes a carrier inside the server: the server spawns the decoder with a fixed three-word argv.
    """
    decoder = os.environ.get("XAX_MCP_TEST_CONSTRUCT")
    if not decoder:
        pytest.skip("set XAX_MCP_TEST_CONSTRUCT (native XAX construct executable) to drive the native decoder")
    request_bytes = (TOOLING / "programs" / "sandbox_request.json").read_bytes()
    store = (TOOLING / "programs" / "xax-mcp-sandbox.xax").read_bytes()
    assert request_bytes == (_native() / "sandbox_request.json").read_bytes()
    assert store == (_native() / "xax-mcp-sandbox-gen0.xax").read_bytes()
    request = json.loads(request_bytes)
    work = tmp_path / "work"
    work.mkdir()
    server = Server(exe, env={"XAX_MCP_WORK": str(work), "XAX_MCP_CONSTRUCT": decoder})
    try:
        result = server.call("xax_construct", {"request": request})
        current = work / "current.xax"
        assert result == {"bytes": len(store), "ok": True, "root": store[7:39].hex(), "workspace": "ws_0"}, result
        assert current.read_bytes() == store
        # a carrier the decoder refuses is reported, and the current store is left exactly as it was
        refused = server.call("xax_construct", {"request": {"format": "xax-construct-v0", "platform": "windows-x86_64",
                                                            "functions": [{}], "package": {}}})
        assert refused["error"]["code"] == "construct_rejected", refused
        assert current.read_bytes() == store
        # the request must be a JSON object and it must be present
        assert server.call("xax_construct", {"request": 7})["error"]["code"] == "invalid_request"
        assert server.call("xax_construct", {})["error"]["code"] == "invalid_request"
    finally:
        code, rest, err = server.close()
        assert code == 0 and not rest, (code, rest, err)
    # the grant is the decoder and the work directory together: either one missing fails closed before spawning
    for env in ({"XAX_MCP_CONSTRUCT": decoder}, {"XAX_MCP_WORK": str(work)},
                {"XAX_MCP_WORK": str(work), "XAX_MCP_CONSTRUCT": str(tmp_path / "missing-construct.exe")}):
        other = Server(exe, env=env)
        try:
            error = other.call("xax_construct", {"request": request})["error"]
            expected = "construct_rejected" if "missing-construct.exe" in env.get("XAX_MCP_CONSTRUCT", "") else "denied_capability"
            assert error["code"] == expected, (env, error)
        finally:
            assert other.close()[0] == 0



def test_sandbox_runs_the_seed_artifact(tmp_path):
    """The native executor runs the committed seed artifact and records its exit code.

    The launcher and the seed artifact are the committed ``native/*.exe`` files; the source stores in ``programs/``
    must be byte-identical.  The executor creates a capability-less AppContainer inside a job object (see
    docs/NATIVE.md); this test only asserts that the artifact ran and its exit code was captured.  A host that cannot
    create or hold the container makes the executor fail closed (exit 51 or 41), which skips this test with that reason.
    """
    launcher = _native() / "xax-mcp-sandbox.exe"
    seed = _native() / "xax-mcp-seed.exe"
    if not launcher.is_file() or not seed.is_file():
        pytest.skip("the committed executor and seed PEs are not in XAX_MCP_HOME/native")
    assert (TOOLING / "programs" / "xax-mcp-sandbox.xax").read_bytes() == (
        _native() / "xax-mcp-sandbox-gen0.xax").read_bytes()
    assert (TOOLING / "programs" / "xax-mcp-seed.xax").read_bytes() == (_native() / "xax-mcp-seed.xax").read_bytes()
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    ran = subprocess.run([str(launcher), str(seed), str(work)], capture_output=True, timeout=120)
    if ran.returncode in (41, 51):
        # the executor fails closed when this host cannot create or hold an AppContainer; say so instead of
        # pretending the artifact ran confined
        pytest.skip(f"this host cannot provide the AppContainer confinement (launcher exit {ran.returncode})")
    assert ran.returncode == 0, ran.stderr.decode(errors="replace")
    result = (work / "sandbox-result.bin").read_bytes()
    assert len(result) == 16
    exit_code = int.from_bytes(result[0:4], "little")
    flags = int.from_bytes(result[4:8], "little")
    assert (exit_code, flags) == (40, 0), (exit_code, flags, ran.returncode)  # the seed calls ExitProcess(40)
    assert (work / "sandbox-out.bin").read_bytes() == b"" and (work / "sandbox-err.bin").read_bytes() == b""


def test_overlong_compiler_grant_fails_closed(exe, tmp_path):
    """A truncated compiler/work/store value is treated as no grant, never as a shorter path."""
    overlong = "x" * 600
    server = Server(exe, env={"XAX_MCP_COMPILER": overlong, "XAX_MCP_WORK": str(tmp_path), "XAX_MCP_STORE": overlong})
    try:
        error = server.call("xax_query", {})["error"]
        assert error["code"] == "denied_capability" and "XAX_MCP_COMPILER" in error["message"]
    finally:
        code, rest, err = server.close()
        assert code == 0 and not rest, (code, rest, err)
