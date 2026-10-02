"""Browser platform package and generated host page (``wasm32-browser-v1``, ADR-103).

A browser cannot run a WebAssembly module without a JavaScript host, so the
page's script is platform glue.  It is never written by hand: each
``xax-web-v1`` declaration below has exactly one fixed host meaning, and
:func:`emit_browser_page` generates the script from the declarations the
module actually imports.  Unused bindings emit nothing.  The page adds no
runtime, allocator, or event loop of its own; ``_start`` runs once after
instantiation, and the program's bindings run synchronously inside it.

Host state (the document and the URL) is ordered by one ``effect<io>``
token that the host supplies to ``_start``.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from xax_compiler import (
    EffectDomain,
    Permission,
    SemanticObject,
    bits_type,
    decode_foreign_function,
    effect_type,
    fail,
    foreign_function_symbol,
    memory_effect_type,
    pointer_type,
)
from xax_wasm import WasmImage

WEB_LIBRARY = b"xax-web-v1"
_ABI = b"wasm32-import"


@dataclass(frozen=True)
class WebApi:
    """Typed ``xax-web-v1`` bindings.  Byte pointers address the module's exported memory."""

    b8: SemanticObject
    b32: SemanticObject
    bytes_rw: SemanticObject
    bytes_read: SemanticObject
    memory_effect: SemanticObject
    page_effect: SemanticObject
    query_copy: SemanticObject
    set_body_text: SemanticObject

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (self.b8, self.b32, self.bytes_rw, self.bytes_read, self.memory_effect, self.page_effect)

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (self.query_copy, self.set_body_text)


def web_api() -> WebApi:
    b8, b32 = bits_type(8), bits_type(32)
    bytes_rw = pointer_type(b8, Permission.READ_WRITE, 1)
    bytes_read = pointer_type(b8, Permission.READ, 1)
    memory = memory_effect_type()
    page = effect_type(EffectDomain.IO, 0)

    def binding(name: bytes, inputs, outputs) -> SemanticObject:
        return foreign_function_symbol(WEB_LIBRARY, name, inputs, outputs, abi=_ABI)

    return WebApi(
        b8, b32, bytes_rw, bytes_read, memory, page,
        # Copies the UTF-8 query string (without "?") into [buffer, buffer + capacity)
        # and returns its full byte length; a result above capacity reports truncation.
        binding(b"query_copy", (bytes_rw, b32, page, memory), (b32, page, memory)),
        # Replaces the body's text with the UTF-8 bytes [buffer, buffer + length).
        binding(b"set_body_text", (bytes_read, b32, page, memory), (page, memory)),
    )


# The one host meaning of each binding.  ``view()`` is the current byte view of
# the module memory (it is re-read because memory may grow).
_HOST = {
    b"query_copy": "(p, n) => { const b = new TextEncoder().encode(location.search.slice(1)); view().set(b.subarray(0, n), p); return b.length; }",
    b"set_body_text": "(p, n) => { document.body.textContent = new TextDecoder().decode(view().subarray(p, p + n)); }",
}


def _imports(module: bytes) -> list[tuple[bytes, bytes]]:
    """``(module, name)`` of each function import, in import-section order."""
    position, imports = 8, []
    while position < len(module):
        section, position = module[position], position + 1
        size, position = _uleb(module, position)
        if section == 2:
            cursor = position
            count, cursor = _uleb(module, cursor)
            for _ in range(count):
                length, cursor = _uleb(module, cursor)
                library, cursor = module[cursor:cursor + length], cursor + length
                length, cursor = _uleb(module, cursor)
                name, cursor = module[cursor:cursor + length], cursor + length
                cursor += 1  # function import kind
                _index, cursor = _uleb(module, cursor)
                imports.append((library, name))
        position += size
    return imports


def _uleb(data: bytes, position: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, position


def emit_browser_page(image: WasmImage, api: WebApi | None = None) -> bytes:
    """One self-contained, deterministic HTML page: the module plus generated host bindings.

    Every import must be one of this package's declarations; anything else
    rejects, because the page would otherwise need a hand-written host.
    """
    api = api or web_api()
    declared = {decode_foreign_function(symbol).name for symbol in api.symbols}
    entries = []
    for library, name in _imports(image.module):
        if library != WEB_LIBRARY or name not in declared:
            fail("XAX.WEB.IMPORT", image.target_cid.hex(), "WEB-IMPORT-DECLARED", [item.decode() for item in sorted(declared)], (library + b"." + name).decode("ascii", "replace"))
        entries.append(f"{json.dumps(name.decode())}: {_HOST[name]}")
    module = base64.b64encode(image.module).decode("ascii")
    script = (
        f'const bytes = Uint8Array.from(atob("{module}"), c => c.charCodeAt(0));\n'
        "let memory;\n"
        "const view = () => new Uint8Array(memory.buffer);\n"
        f"const imports = {{{json.dumps(WEB_LIBRARY.decode())}: {{\n" + "".join(f"  {entry},\n" for entry in entries) + "}};\n"
        "const { instance } = await WebAssembly.instantiate(bytes, imports);\n"
        "memory = instance.exports.memory;\n"
        "instance.exports._start();\n"
    )
    return ('<!doctype html>\n<meta charset="utf-8">\n<title>XAX</title>\n<body>\n<script type="module">\n' + script + "</script>\n").encode("utf-8")


_PLAYWRIGHT_SCRIPT = """
const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  await page.goto(process.argv[1]);
  await page.waitForFunction(() => document.body && document.body.textContent.length > 0, null, { timeout: 10000 }).catch(() => {});
  const text = await page.evaluate(() => document.body.textContent);
  console.log(JSON.stringify({ text, errors, version: browser.version() }));
  await browser.close();
})();
"""


def playwright_available() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    completed = subprocess.run([node, "-e", 'require("playwright")'], capture_output=True, env=_node_environment(), check=False)
    return completed.returncode == 0


def _node_environment() -> dict[str, str]:
    environment = dict(os.environ)
    global_modules = os.path.join(os.path.dirname(os.path.dirname(shutil.which("node") or "/")), "lib", "node_modules")
    environment["NODE_PATH"] = os.pathsep.join(item for item in (environment.get("NODE_PATH"), global_modules) if item)
    return environment


def run_browser_page(page: bytes, query: str = "", timeout: float = 60.0) -> dict:
    """Test harness only: load the page in headless Chromium and return the body text, page errors, and browser version."""
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "index.html")
        with open(path, "wb") as handle:
            handle.write(page)
        url = "file://" + path + (f"?{query}" if query else "")
        completed = subprocess.run(
            [shutil.which("node") or "node", "-e", _PLAYWRIGHT_SCRIPT, url],
            capture_output=True, text=True, timeout=timeout, env=_node_environment(), check=False,
        )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or f"browser host exited {completed.returncode}")
    return json.loads(completed.stdout)
