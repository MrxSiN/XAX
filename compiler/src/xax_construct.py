"""General construction carrier ``xax-construct-v1`` (ADR-210): tooling, not source.

An AI constructs a new XAX program by sending one typed request (a tool-call argument).  This module decodes it
into canonical semantic objects and returns a verified store; the request is transport and never enters semantic
identity.  After construction the store is authoritative and is changed only through workspace transactions.

Request (JSON-compatible)::

    {"format": "xax-construct-v1",
     "platform": "linux-x86_64" | "linux-aarch64" | "windows-x86_64" | "jvm",
     "types": {"alias": TYPE, ...},
     "functions": [{"name": N, "params": [TYPE...], "returns": [TYPE...], "blocks": [BLOCK...]}, ...],
     "package": {"name": NAME, "entries": {"app": FUNCTION_NAME, ...}, "release": "app"}}

``TYPE``: ``"b<N>"``, a ``types`` alias, a platform type ``"linux.<name>"``, ``{"view": EXTENT}`` (heap view),
or ``{"ptr": [ELEMENT, "r"|"rw", ALIGNMENT, SPACE]}``.

``BLOCK``: ``{"params": [TYPE...], "nodes": [NODE...], "end": TERMINATOR}``.  ``NODE`` is
``[OPERATION, [OPERAND...], [RESULT_TYPE...], EXTRA?]`` with ``OPERATION`` an operation name (``"add.wrap"``,
``"int.compare"``, ...), or ``["const", TYPE, INTEGER]``.  ``EXTRA`` may hold ``"attrs"`` (integers; compare kinds
by name) and ``"entity"`` (``"linux.<symbol>"``, ``"linux.startup.<symbol>"``, ``{"linux.munmap_view": [TYPE, EXTENT]}``,
``{"fn": NAME}``).  ``linux.startup.*`` are the ``linux-x86_64-startup-v1`` reads of the initial process stack (``argc``,
``arg_length``, ``arg_copy``, ``envc``, ``env_length``, ``env_copy``, ``auxv_value``; ADR-094); like every startup read
they are valid only in the process entry function, and a build rejects them elsewhere (ADR-223).
Operands name values: ``"p<i>"``/``"n<i>"``/``"n<i>.r<k>"`` in the current block, or ``"B<b>.p<i>"`` and
``"B<b>.n<i>[.r<k>]"`` in a dominating block.  A literal operand ``[TYPE, INTEGER]`` is a constant.
``TERMINATOR``: ``["ret", [V...]]``, ``["br", B, [V...]]``, ``["cbr", V, B, [V...], B, [V...]]``.

Platform ``linux-aarch64`` (ADR-258) builds an ``aarch64-linux-elf-exec-v1`` static executable from the same ``linux.``
names, resolved in ``xax_linux_aarch64.linux_aarch64_api`` (same names and shapes); it has no startup reads.

Platform ``windows-x86_64`` (ADR-252) builds an ``x86_64-windows-pe-v1`` PE32+ executable instead.  Its platform names
use the ``win32.`` prefix in place of ``linux.``: the types and symbols of ``xax_platform.win32_kernel32_api`` and
``win32_stdio_api`` (the stdio ``read_file``/``write_file`` take heap-view pointers), plus
``{"win32.virtual_free_view": [TYPE, EXTENT]}``.  There are no startup reads; the entry ends with ``win32.exit_process``.
A ``windows-x86_64`` package may add ``"exports": {"ExportName": FUNCTION_NAME, ...}`` (ADR-259): the build is then a
PE32+ DLL named ``<package name>.dll`` that exports those functions under ``win64-c`` and has no DllMain; the release
entry must be one of the exported functions.
On ``windows-x86_64`` an entity may also declare a foreign call by its exact typed interface (ADR-260):
``{"win32.import": [DLL, SYMBOL, [TYPE...], [TYPE...]]}`` is a ``win64-c`` import (``DLL`` a bare file name), and
``{"win32.com": [INTERFACE, SLOT, [TYPE...], [TYPE...]]}`` is method ``SLOT`` of a COM interface (a ``win64-c`` declaration on ``com:INTERFACE``): input 0
is the ``b64`` interface pointer and the callee is read from its vtable at the call.

Platform ``jvm`` (ADR-257) builds an executable JAR (``jvm-classfile-memory``: one linear memory and the standard
streams as generated members of the program's own class).  Its names use the ``jvm.`` prefix: the types and symbols of
``xax_jvm.jvm_memory_api`` (``read``, ``write``, ``mmap_anonymous``, ``exit_group``, ...), the same names and shapes as
the Linux ones, plus ``{"jvm.munmap_view": [TYPE, EXTENT]}``.  There are no startup reads.

Functions are listed callees first.  The result store's root is the build snapshot of the ``release`` entry; the
package declares every entry (``app``, ``test``, ...) so every build is a canonical request against it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from xax_compiler import (
    IntCompare, Kind, Operation, Permission, SemanticObject, StoreReader, ValueRef, aarch64_linux_exec_target, bits_type, heap_view_type,
    jvm_classfile_memory_target, object_with_refs, pointer_type, x86_64_linux_exec_target, x86_64_windows_pe_target,
)
from xax_graph_builder import GraphBuilder

FORMAT = "xax-construct-v1"
_PLATFORMS = ("linux-x86_64", "linux-aarch64", "windows-x86_64", "jvm")


@dataclass(frozen=True)
class Constructed:
    reader: StoreReader
    package: SemanticObject
    target: SemanticObject
    profile: SemanticObject
    policy: SemanticObject
    functions: dict[str, SemanticObject]
    release_request: SemanticObject


def _error(message: str) -> ValueError:
    return ValueError(f"xax-construct: {message}")


class _Builder:
    def __init__(self, request: dict):
        from xax_linux import linux_api, linux_startup_api
        from xax_platform import win32_kernel32_api, win32_stdio_api

        if request.get("format") != FORMAT:
            raise _error(f"format must be {FORMAT}")
        if request.get("platform") not in _PLATFORMS:
            raise _error(f"platform must be one of {_PLATFORMS}")
        from xax_build import ArtifactKind

        self.artifact = ArtifactKind.NATIVE_IMAGE
        if request["platform"] == "jvm":
            from xax_jvm import jvm_memory_api

            self.api = jvm_memory_api()
            self.prefix, self.namespaces, self.platform_types = "jvm.", (self.api,), self.api.types
            self.startup = None
            self.target = jvm_classfile_memory_target()
            self.artifact = ArtifactKind.JVM_EXECUTABLE_JAR
        elif request["platform"] == "linux-x86_64":
            self.api = linux_api()
            self.prefix, self.namespaces, self.platform_types = "linux.", (self.api,), self.api.types
            self.startup = linux_startup_api(self.api)
            self.target = x86_64_linux_exec_target()
        elif request["platform"] == "linux-aarch64":
            from xax_linux_aarch64 import linux_aarch64_api

            self.api = linux_aarch64_api()
            self.prefix, self.namespaces, self.platform_types = "linux.", (self.api,), self.api.types
            self.startup = None
            self.target = aarch64_linux_exec_target()
        else:
            self.api = win32_kernel32_api()
            stdio = win32_stdio_api(self.api)
            # stdio first: its heap-pointer write_file is the one a carrier program can call.
            self.prefix, self.namespaces, self.platform_types = "win32.", (stdio, self.api), (*self.api.types, *stdio.types)
            self.startup = None
            self.target = x86_64_windows_pe_target()
        self.aliases = dict(request.get("types", {}))
        self.functions: dict[str, SemanticObject] = {}
        self.objects: dict[bytes, SemanticObject] = {}

    def type(self, spec, seen=()) -> SemanticObject:
        if isinstance(spec, str):
            if spec in self.aliases:
                if spec in seen:
                    raise _error(f"type alias cycle at {spec}")
                return self.type(self.aliases[spec], (*seen, spec))
            if re.fullmatch(r"b[1-9][0-9]*", spec):
                return bits_type(int(spec[1:]))
            if spec.startswith(self.prefix) and (value := self._platform(spec)) is not None and value.kind == Kind.TYPE:
                return value
            raise _error(f"unknown type {spec!r}")
        if isinstance(spec, dict) and set(spec) == {"view"} and type(spec["view"]) is int and spec["view"] > 0:
            return heap_view_type(spec["view"])
        if isinstance(spec, dict) and set(spec) == {"ptr"} and isinstance(spec["ptr"], list) and len(spec["ptr"]) == 4:
            element, permission, alignment, space = spec["ptr"]
            if permission not in ("r", "rw") or type(alignment) is not int or type(space) is not int:
                raise _error(f"bad pointer type {spec!r}")
            return pointer_type(self.type(element, seen), Permission.READ if permission == "r" else Permission.READ_WRITE, alignment, space=space)
        raise _error(f"bad type {spec!r}")

    def entity(self, spec) -> SemanticObject:
        if isinstance(spec, str) and self.startup is not None and spec.startswith("linux.startup."):
            name = spec[len("linux.startup."):]
            if name in self.startup.__dataclass_fields__:
                return getattr(self.startup, name)
            raise _error(f"unknown entity {spec!r}")
        if isinstance(spec, str) and spec.startswith(self.prefix):
            value = self._platform(spec)
            if value is not None and value.kind != Kind.TYPE:
                return value
        if isinstance(spec, dict) and len(spec) == 1:
            (key, value), = spec.items()
            if key == "fn" and value in self.functions:
                return self.functions[value]
            if key in ("win32.import", "win32.com") and self.prefix == "win32." and isinstance(value, list) and len(value) == 4:
                return self._win32_declaration(key, *value)
            if isinstance(value, list) and len(value) == 2 and type(value[1]) is int:
                if (key, self.prefix) in (("linux.munmap_view", "linux."), ("jvm.munmap_view", "jvm.")):
                    return self.api.munmap_view(self.type(value[0]), value[1])
                if key == "win32.virtual_free_view" and self.prefix == "win32.":
                    return self.api.virtual_free_view(heap_view_type(value[1]), self.type(value[0]))
        raise _error(f"unknown entity {spec!r}")

    def _win32_declaration(self, key: str, owner, member, inputs, outputs) -> SemanticObject:
        """ADR-260: a ``win64-c`` import ``[DLL, SYMBOL, INPUTS, OUTPUTS]`` or a COM method
        ``[INTERFACE, SLOT, INPUTS, OUTPUTS]``; the exact typed interface is the declaration's identity."""
        from xax_compiler import foreign_function_symbol, win64_com_method

        if not isinstance(inputs, list) or not isinstance(outputs, list):
            raise _error(f"{key} needs input and output type lists")
        types = (tuple(self.type(spec) for spec in inputs), tuple(self.type(spec) for spec in outputs))
        if key == "win32.import":
            # A bare module file name: the Windows loader resolves it (KnownDLLs/System32 first for system DLLs).
            if not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}\.dll", owner, re.IGNORECASE) \
                    or not isinstance(member, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", member):
                raise _error(f"win32.import needs a bare DLL file name and a C symbol: {owner!r} {member!r}")
            return foreign_function_symbol(owner.encode(), member.encode(), *types, abi=b"win64-c")
        if not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", owner) or type(member) is not int:
            raise _error(f"win32.com needs an interface name and an integer slot: {owner!r} {member!r}")
        try:
            return win64_com_method(owner.encode(), member, *types)
        except ValueError as error:
            raise _error(f"win32.com {owner}: {error}") from None

    def _platform(self, spec: str) -> SemanticObject | None:
        for namespace in self.namespaces:
            value = getattr(namespace, spec[len(self.prefix):], None)
            if isinstance(value, SemanticObject):
                return value
        return None

    def function(self, record: dict) -> SemanticObject:
        if set(record) != {"name", "params", "returns", "blocks"} or not record["blocks"]:
            raise _error("function needs name, params, returns, blocks")
        name = record["name"]
        if name in self.functions:
            raise _error(f"duplicate function {name}")
        graph = GraphBuilder()
        blocks = [graph.block(*(self.type(spec) for spec in block.get("params", []))) for block in record["blocks"]]
        named: list[dict[str, ValueRef]] = [{f"p{i}": value for i, value in enumerate(block.params)} for block in blocks]

        def value(spec, here: int) -> ValueRef:
            if isinstance(spec, list) and len(spec) == 2 and type(spec[1]) is int:
                return blocks[here].const(self.type(spec[0]), spec[1])
            if not isinstance(spec, str):
                raise _error(f"{name}: bad operand {spec!r}")
            match = re.fullmatch(r"(?:B([0-9]+)\.)?((?:p|n)[0-9]+(?:\.r[0-9]+)?)", spec)
            if match is None:
                raise _error(f"{name}: bad operand {spec!r}")
            index = here if match.group(1) is None else int(match.group(1))
            key = match.group(2)
            if key.endswith(".r0"):
                key = key[:-3]
            if index >= len(blocks) or key not in named[index]:
                raise _error(f"{name}: unbound operand {spec!r} in block {here}")
            return named[index][key]

        for here, (block, spec) in enumerate(zip(blocks, record["blocks"])):
            for index, node in enumerate(spec.get("nodes", [])):
                if not isinstance(node, list) or not node or not isinstance(node[0], str):
                    raise _error(f"{name}: bad node {node!r}")
                if node[0] == "const":
                    if len(node) != 3 or type(node[2]) is not int:
                        raise _error(f"{name}: const needs a type and an integer")
                    results = (block.const(self.type(node[1]), node[2]),)
                else:
                    if len(node) not in (3, 4):
                        raise _error(f"{name}: node needs operation, operands, results")
                    try:
                        operation = Operation[node[0].upper().replace(".", "_")]
                    except KeyError:
                        raise _error(f"{name}: unknown operation {node[0]!r}") from None
                    extra = node[3] if len(node) == 4 else {}
                    if set(extra) - {"attrs", "entity"}:
                        raise _error(f"{name}: unknown node field in {extra!r}")
                    attributes = tuple(
                        IntCompare[item.upper()] if isinstance(item, str) else item for item in extra.get("attrs", ())
                    )
                    entity = self.entity(extra["entity"]) if "entity" in extra else None
                    results = block.op(operation, tuple(value(item, here) for item in node[1]),
                                       tuple(self.type(item) for item in node[2]), entity=entity, attributes=attributes)
                for result, ref in enumerate(results):
                    named[here][f"n{index}" if result == 0 else f"n{index}.r{result}"] = ref
            end = spec.get("end")
            if not isinstance(end, list) or not end:
                raise _error(f"{name}: block {here} needs an end")
            if end[0] == "ret" and len(end) == 2:
                block.ret(*(value(item, here) for item in end[1]))
            elif end[0] == "br" and len(end) == 3 and type(end[1]) is int and end[1] < len(blocks):
                block.br(blocks[end[1]], *(value(item, here) for item in end[2]))
            elif end[0] == "cbr" and len(end) == 6 and all(type(end[i]) is int and end[i] < len(blocks) for i in (2, 4)):
                block.cbr(value(end[1], here), blocks[end[2]], tuple(value(item, here) for item in end[3]),
                          blocks[end[4]], tuple(value(item, here) for item in end[5]))
            else:
                raise _error(f"{name}: bad end {end!r}")
        result = graph.function(tuple(self.type(spec) for spec in record["params"]), tuple(self.type(spec) for spec in record["returns"]))
        self.objects.update(graph.objects)
        self.functions[name] = result
        return result


def construct(request: dict) -> Constructed:
    """Decode one ``xax-construct-v1`` request into a verified canonical build snapshot store."""
    from xax_build import ArtifactKind, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy

    builder = _Builder(request)
    if set(request) - {"format", "platform", "types", "functions", "package"}:
        raise _error("unknown request field")
    for record in request.get("functions", []):
        builder.function(record)
    spec = request.get("package")
    if not isinstance(spec, dict) or set(spec) - {"exports"} != {"name", "entries", "release"} or not spec["entries"]:
        raise _error("package needs name, entries, release")
    exports = ()
    if "exports" in spec:
        from xax_build import ArtifactKind
        from xax_compiler import windows_export_symbol

        if request["platform"] != "windows-x86_64" or not spec["exports"] or any(f not in builder.functions for f in spec["exports"].values()):
            raise _error("exports need windows-x86_64 and must name constructed functions")
        if spec["entries"][spec["release"]] not in spec["exports"].values():
            raise _error("the release entry of a DLL must be exported")
        exports = tuple(windows_export_symbol(builder.functions[f], name.encode()) for name, f in sorted(spec["exports"].items()))
        builder.artifact = ArtifactKind.WINDOWS_DLL
    entries = tuple((name.encode(), builder.functions[function]) for name, function in sorted(spec["entries"].items()) if function in builder.functions)
    if len(entries) != len(spec["entries"]) or spec["release"] not in spec["entries"]:
        raise _error("package entries must name constructed functions, and release must be an entry")
    module = object_with_refs(Kind.MODULE, (*builder.functions.values(), *exports))
    app = package(spec["name"].encode(), (module,), build_entries=entries)
    profile, policy = build_profile(), trust_policy()
    request_object = build_request(app, spec["release"].encode(), builder.target, profile, requested_artifacts=(builder.artifact,))
    everything = (*builder.objects.values(), *builder.platform_types, *exports, module, app, builder.target, profile, policy, request_object)
    reader = snapshot_store(resolve_packages(request_object, everything, policy, b"xax-construct-v1"), everything)
    return Constructed(reader, app, builder.target, profile, policy, dict(builder.functions), request_object)
