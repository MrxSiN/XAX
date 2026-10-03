"""Deterministic C header importer (ADR-127, OI-32): clang AST -> typed foreign declarations.

Tooling, not semantics: the output is ordinary ``foreign_function_symbol``
declarations (canonical XAX objects) plus a JSON import report.  Nobody writes
wrapper source.

* Source: ``clang -Xclang -ast-dump=json -fsyntax-only`` over the named
  headers.  The report records each header's SHA-256 and the clang version,
  so an import is reproducible from its declared inputs (OI-30).
* Selection: the caller names every function to import and its soname;
  headers never imply a library, and an unknown name is an error.
* Types (LP64: Linux x86-64 and AArch64): ``char``/``short``/``int``/``long``/
  ``long long`` and their unsigned forms map to ``bits<8/16/32/64/64>``;
  ``_Bool`` to ``bits<8>`` (its ABI width); ``float``/``double`` to f32/f64;
  ``const T *`` and ``T *`` for a scalar or ``void`` ``T`` to read-only or
  read-write byte pointers; a pointer to a ``struct``/``union`` to an opaque
  identity handle that no XAX memory operation accepts.  A function pointer
  parameter becomes the C code-entry type (ADR-102).  By-value structs and
  unions, arrays, ``long double``, and variadic functions are refused with a
  reason, never guessed.
* Contract: every import takes and returns one memory frontier, because a C
  function may touch hidden global state (``errno``, buffers, locale).  An
  explicit ``overrides`` table may state stronger facts (``pure``: no
  frontier); nothing is inferred from names.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from xax_compiler import (
    AAPCS64_LINUX_C_ABI,
    AAPCS64_STATIC_C_ABI,
    FloatFormat,
    Permission,
    SYSV_X86_64_C_ABI,
    SemanticObject,
    bits_type,
    float_type,
    foreign_entry_code_type,
    foreign_entry_pointer_type,
    foreign_function_symbol,
    memory_effect_type,
    opaque_identity_type,
    pointer_type,
)

_INTEGERS = {
    "char": 8, "signed char": 8, "unsigned char": 8, "_Bool": 8, "bool": 8,
    "short": 16, "unsigned short": 16, "short int": 16, "unsigned short int": 16,
    "int": 32, "unsigned int": 32, "unsigned": 32, "signed int": 32,
    "long": 64, "unsigned long": 64, "long int": 64, "unsigned long int": 64,
    "long long": 64, "unsigned long long": 64, "long long int": 64, "unsigned long long int": 64,
}
_FLOATS = {"float": FloatFormat.BINARY32, "double": FloatFormat.BINARY64}
_QUALIFIERS = re.compile(r"\b(const|volatile|restrict|__restrict)\b")
# Pointer type CID -> the element objects it references (for store closure).
_ELEMENTS: dict[bytes, tuple[SemanticObject, ...]] = {}


def _pointer(element: SemanticObject, permission: Permission) -> SemanticObject:
    pointer = pointer_type(element, permission, 1, space=2)
    _ELEMENTS[pointer.cid] = (element,)
    return pointer


class ImportRefused(ValueError):
    """A declaration outside the importer's exact subset."""


@dataclass(frozen=True)
class ImportedFunction:
    name: str
    declaration: SemanticObject
    c_type: str
    inputs: tuple[SemanticObject, ...] = ()
    outputs: tuple[SemanticObject, ...] = ()


@dataclass(frozen=True)
class CImport:
    functions: tuple[ImportedFunction, ...]
    report: dict = field(hash=False)

    def __getitem__(self, name: str) -> SemanticObject:
        return self.function(name).declaration

    def function(self, name: str) -> ImportedFunction:
        return next(item for item in self.functions if item.name == name)

    @property
    def objects(self) -> tuple[SemanticObject, ...]:
        """Every declaration and type object (with referenced element types) a store needs."""
        found: dict[bytes, SemanticObject] = {}

        def add(item: SemanticObject) -> None:
            if item.cid not in found:
                found[item.cid] = item
                for reference in _ELEMENTS.get(item.cid, ()):
                    add(reference)

        for function in self.functions:
            for item in (function.declaration, *function.inputs, *function.outputs):
                add(item)
        return tuple(found.values())


def _clang_ast(headers: Sequence[Path], clang: str, flags: Sequence[str]) -> list[dict]:
    source = "".join(f'#include "{Path(header).resolve()}"\n' for header in headers)
    completed = subprocess.run(
        [clang, "-x", "c", "-std=c11", "-Xclang", "-ast-dump=json", "-fsyntax-only", *flags, "-"],
        input=source.encode(), capture_output=True, check=True,
    )
    return json.loads(completed.stdout).get("inner", [])


class _Types:
    def __init__(self, nodes: Sequence[dict]):
        self.typedefs: dict[str, str] = {}
        for node in nodes:
            if node.get("kind") == "TypedefDecl" and "name" in node:
                kind = node.get("type", {})
                self.typedefs[node["name"]] = kind.get("desugaredQualType", kind.get("qualType", ""))

    def canonical(self, text: str, depth: int = 0) -> str:
        """Resolve typedef names in a simple C type string (no function types)."""
        if depth > 32:
            raise ImportRefused(f"typedef chain too deep: {text}")
        text = " ".join(text.split())
        stars = text.count("*")
        base = text.replace("*", " ").strip()
        constant = bool(re.search(r"\bconst\b", base))
        base = " ".join(_QUALIFIERS.sub(" ", base).split())
        if base in self.typedefs and not base.startswith(("struct ", "union ", "enum ")):
            target = " ".join(self.typedefs[base].split())
            if target == base:
                # An anonymous `typedef struct {...} name`: clang spells it by name.
                return ("const " if constant else "") + "struct " + base + (" " + "*" * stars if stars else "")
            if "(*)" in target:
                if stars:
                    raise ImportRefused(f"pointer to a function pointer {text!r}")
                return target
            resolved = self.canonical(target, depth + 1)
            if stars:
                resolved_stars = resolved.count("*")
                inner = resolved.replace("*", "").strip()
                constant = constant or "const " in resolved.split("*")[0]
                return ("const " if constant else "") + " ".join(_QUALIFIERS.sub(" ", inner).split()) + " " + "*" * (stars + resolved_stars)
            return ("const " if constant and "*" not in resolved else "") + resolved
        return ("const " if constant else "") + base + (" " + "*" * stars if stars else "")


def _value_type(text: str, types: _Types, abi: bytes) -> SemanticObject:
    if "(*)" not in text and "(^)" not in text:
        resolved = types.canonical(text)
        text = resolved if "(*)" in resolved else text
    if "(*)" in text or "(^)" in text:
        if abi != SYSV_X86_64_C_ABI:
            raise ImportRefused("C-callable XAX entries exist only for sysv-x86_64-c (ADR-102)")
        entry = foreign_entry_pointer_type(abi)
        _ELEMENTS[entry.cid] = (foreign_entry_code_type(abi),)
        return entry
    canonical = types.canonical(text)
    stars = canonical.count("*")
    base = canonical.replace("*", "").strip()
    constant = base.startswith("const ")
    base = base.removeprefix("const ").strip()
    if base.startswith("enum "):
        base = "int"
    if stars == 0:
        if base in _INTEGERS:
            return bits_type(_INTEGERS[base])
        if base in _FLOATS:
            return float_type(_FLOATS[base])
        raise ImportRefused(f"by-value type {canonical!r} (structs, unions, arrays, long double: OI-40)")
    if stars > 1:
        return opaque_identity_type(b"c-ptr:" + canonical.encode())
    if base.startswith(("struct ", "union ")) or (base not in _INTEGERS and base not in _FLOATS and base != "void"):
        # A handle: C owns the layout, XAX never dereferences it.
        return _pointer(opaque_identity_type(b"c:" + base.encode()), Permission.READ_WRITE)
    return _pointer(bits_type(8), Permission.READ if constant else Permission.READ_WRITE)


def _split_parameters(signature: str) -> tuple[str, list[str], bool]:
    """``ret (a, b, ...)`` -> (ret, [a, b], variadic) with function-pointer parameters intact."""
    depth, split = 0, None
    for index in range(len(signature) - 1, -1, -1):
        if signature[index] == ")":
            depth += 1
        elif signature[index] == "(":
            depth -= 1
            if depth == 0:
                split = index
                break
    result, inner = signature[:split].strip(), signature[split + 1:-1]
    parts, depth, current = [], 0, ""
    for character in inner:
        if character == "," and depth == 0:
            parts.append(current.strip())
            current = ""
            continue
        depth += character == "("
        depth -= character == ")"
        current += character
    if current.strip():
        parts.append(current.strip())
    variadic = bool(parts) and parts[-1] == "..."
    parts = [part for part in parts if part not in ("...", "void")]
    return result, parts, variadic


def import_c_functions(
    headers: Sequence[str | Path],
    library: bytes,
    names: Sequence[str],
    *,
    abi: bytes = SYSV_X86_64_C_ABI,
    overrides: Mapping[str, str] | None = None,
    clang: str = "clang",
    flags: Sequence[str] = (),
) -> CImport:
    """Import exactly ``names`` from ``headers`` as declarations of ``library``."""
    if abi not in (SYSV_X86_64_C_ABI, AAPCS64_LINUX_C_ABI, AAPCS64_STATIC_C_ABI):
        raise ValueError("the C importer targets sysv-x86_64-c, aapcs64-linux-c, or aapcs64-c")
    overrides = dict(overrides or {})
    unknown = set(overrides.values()) - {"pure"}
    if unknown:
        raise ValueError(f"unknown override facts {sorted(unknown)}")
    nodes = _clang_ast([Path(item) for item in headers], clang, flags)
    types = _Types(nodes)
    declared = {node["name"]: node for node in nodes if node.get("kind") == "FunctionDecl" and "name" in node}
    memory = memory_effect_type()
    functions, refused = [], {}
    for name in names:
        if name not in declared:
            raise ImportRefused(f"{name} is not declared in {[str(item) for item in headers]}")
        signature = declared[name]["type"]["qualType"]
        try:
            result_text, parameter_texts, variadic = _split_parameters(signature)
            if variadic:
                raise ImportRefused("variadic (typed argument packs: OI-40)")
            inputs = [_value_type(text, types, abi) for text in parameter_texts]
            outputs = [] if types.canonical(result_text) == "void" else [_value_type(result_text, types, abi)]
        except ImportRefused as reason:
            refused[name] = str(reason)
            continue
        frontier = [] if overrides.get(name) == "pure" else [memory]
        declaration = foreign_function_symbol(library, name.encode(), (*inputs, *frontier), (*outputs, *frontier), abi=abi)
        functions.append(ImportedFunction(name, declaration, signature, (*inputs, *frontier), (*outputs, *frontier)))
    version = subprocess.run([clang, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    report = {
        "format": "xax-c-import-report-v1",
        "clang": version,
        "headers": {str(item): hashlib.sha256(Path(item).read_bytes()).hexdigest() for item in headers},
        "library": library.decode(),
        "abi": abi.decode(),
        "imported": {item.name: {"c": item.c_type, "declaration": item.declaration.cid.hex()} for item in functions},
        "refused": refused,
        "overrides": overrides,
    }
    return CImport(tuple(functions), report)
