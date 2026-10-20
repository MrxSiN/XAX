"""Generic MCP client walkthrough (official `mcp` SDK, STDIO) against the native XAX server.

    python examples/generic_client.py [--server PATH/TO/xax-mcp-native.exe]

This is an external test client, not part of the server.  It lists the tools, reads the native capability report,
and demonstrates the honest `unsupported` result for a compiler-backed tool.  The current native build does not
construct, build, or execute programs; see docs/NATIVE.md.
"""
from __future__ import annotations

import argparse
import json
import sys

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters


async def main(args) -> int:
    server = StdioServerParameters(command=args.server, args=["--read-only"])
    async with Client(server, read_timeout_seconds=60) as client:
        tools = await client.list_tools()
        print("tools:", [tool.name for tool in tools.tools], file=sys.stderr)
        capabilities = (await client.call_tool("xax_capabilities", {})).structured_content
        print(json.dumps({"server": capabilities["server"],
                          "xax": capabilities["xax"],
                          "rights": capabilities["authority"]["rights"],
                          "maturity": capabilities["maturity"]}, indent=1))
        denied = (await client.call_tool("xax_construct", {"request": {}})).structured_content
        print("xax_construct:", json.dumps(denied, indent=1), file=sys.stderr)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    raise SystemExit(anyio.run(main, parser.parse_args()))
