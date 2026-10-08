"""General construction carrier ``xax-construct-v1`` (ADR-210): tooling, not source.

An AI constructs a new XAX program by sending one typed request (a tool-call argument).  This module decodes it
into canonical semantic objects and returns a verified store; the request is transport and never enters semantic
identity.  After construction the store is authoritative and is changed only through workspace transactions.

Request (JSON-compatible)::

    {"format": "xax-construct-v1",
     "platform": "linux-x86_64",
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
they are valid only in the process entry function, and a build rejects them elsewhere (ADR-222).
Operands name values: ``"p<i>"``/``"n<i>"``/``"n<i>.r<k>"`` in the current block, or ``"B<b>.p<i>"`` and
``"B<b>.n<i>[.r<k>]"`` in a dominating block.  A literal operand ``[TYPE, INTEGER]`` is a constant.
``TERMINATOR``: ``["ret", [V...]]``, ``["br", B, [V...]]``, ``["cbr", V, B, [V...], B, [V...]]``.

Functions are listed callees first.  The result store's root is the build snapshot of the ``release`` entry; the
package declares every entry (``app``, ``test``, ...) so every build is a canonical request against it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from xax_compiler import (
    IntCompare, Kind, Operation, Permission, SemanticObject, StoreReader, ValueRef, bits_type, heap_view_type,
    object_with_refs, pointer_type, x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder

FORMAT = "xax-construct-v1"
_PLATFORMS = ("linux-x86_64",)


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

        if request.get("format") != FORMAT:
            raise _error(f"format must be {FORMAT}")
        if request.get("platform") not in _PLATFORMS:
            raise _error(f"platform must be one of {_PLATFORMS}")
        self.api = linux_api()
        self.startup = linux_startup_api(self.api)
        self.target = x86_64_linux_exec_target()
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
            if spec.startswith("linux."):
                value = getattr(self.api, spec[6:], None)
                if isinstance(value, SemanticObject) and value.kind == Kind.TYPE:
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
        if isinstance(spec, str) and spec.startswith("linux.startup."):
            name = spec[len("linux.startup."):]
            if name in self.startup.__dataclass_fields__:
                return getattr(self.startup, name)
            raise _error(f"unknown entity {spec!r}")
        if isinstance(spec, str) and spec.startswith("linux."):
            value = getattr(self.api, spec[6:], None)
            if isinstance(value, SemanticObject) and value.kind != Kind.TYPE:
                return value
        if isinstance(spec, dict) and len(spec) == 1:
            (key, value), = spec.items()
            if key == "fn" and value in self.functions:
                return self.functions[value]
            if key == "linux.munmap_view" and isinstance(value, list) and len(value) == 2 and type(value[1]) is int:
                return self.api.munmap_view(self.type(value[0]), value[1])
        raise _error(f"unknown entity {spec!r}")

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
    if not isinstance(spec, dict) or set(spec) != {"name", "entries", "release"} or not spec["entries"]:
        raise _error("package needs name, entries, release")
    entries = tuple((name.encode(), builder.functions[function]) for name, function in sorted(spec["entries"].items()) if function in builder.functions)
    if len(entries) != len(spec["entries"]) or spec["release"] not in spec["entries"]:
        raise _error("package entries must name constructed functions, and release must be an entry")
    module = object_with_refs(Kind.MODULE, tuple(builder.functions.values()))
    app = package(spec["name"].encode(), (module,), build_entries=entries)
    profile, policy = build_profile(), trust_policy()
    request_object = build_request(app, spec["release"].encode(), builder.target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
    everything = (*builder.objects.values(), *builder.api.types, module, app, builder.target, profile, policy, request_object)
    reader = snapshot_store(resolve_packages(request_object, everything, policy, b"xax-construct-v1"), everything)
    return Constructed(reader, app, builder.target, profile, policy, dict(builder.functions), request_object)
