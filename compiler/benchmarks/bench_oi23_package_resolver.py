"""OI-23 measurement-only version/range resolver experiment.

The experiment never changes canonical package objects. Compatibility metadata is
an explicitly versioned derived catalog keyed by exact package CID; successful
resolution always produces an exact-root snapshot of immutable package CIDs.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import platform
import statistics
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from blake3 import blake3
from xax_build import package
from xax_compiler import (
    Block,
    Diagnostic,
    Kind,
    Node,
    Operation,
    SemanticObject,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    constant,
    fail,
    function,
    graph_fragment,
    object_with_refs,
    uleb,
)

CATALOG_MAGIC = b"XRV1"
CATALOG_VERSION = 1
SNAPSHOT_MAGIC = b"XRS1"
SNAPSHOT_VERSION = 1
RESOLVER_IDENTITY = b"oi23-exact-range-resolver-v1"
AI_PACKET_VERSION = 1
DEFAULT_LIMITS = None  # initialized after ResolverLimits


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int = 0
    patch: int = 0

    def __post_init__(self) -> None:
        if min(self.major, self.minor, self.patch) < 0:
            raise ValueError("version components must be non-negative")

    def encoded(self) -> bytes:
        return uleb(self.major) + uleb(self.minor) + uleb(self.patch)

    def label(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class VersionConstraint:
    exact: Version | None = None
    lower: Version | None = None
    upper: Version | None = None  # exclusive

    def __post_init__(self) -> None:
        if self.exact is not None:
            if self.lower is not None or self.upper is not None:
                raise ValueError("exact constraint cannot also carry a range")
        elif self.lower is None or self.upper is None or not self.lower < self.upper:
            raise ValueError("range constraint requires lower < exclusive upper")

    @classmethod
    def exact_version(cls, value: Version) -> "VersionConstraint":
        return cls(exact=value)

    @classmethod
    def range(cls, lower: Version, upper: Version) -> "VersionConstraint":
        return cls(lower=lower, upper=upper)

    def allows(self, value: Version) -> bool:
        if self.exact is not None:
            return value == self.exact
        assert self.lower is not None and self.upper is not None
        return self.lower <= value < self.upper

    def encoded(self) -> bytes:
        if self.exact is not None:
            return b"\x01" + self.exact.encoded()
        assert self.lower is not None and self.upper is not None
        return b"\x02" + self.lower.encoded() + self.upper.encoded()

    def display(self) -> str:
        if self.exact is not None:
            return "=" + self.exact.label()
        assert self.lower is not None and self.upper is not None
        return f"[{self.lower.label()},{self.upper.label()})"


@dataclass(frozen=True)
class Requirement:
    exact_root: bytes | None = None
    logical_identity: bytes | None = None
    constraint: VersionConstraint | None = None

    def __post_init__(self) -> None:
        exact = self.exact_root is not None
        logical = self.logical_identity is not None
        if exact == logical:
            raise ValueError("requirement must be exact-root or logical-versioned")
        if exact:
            if len(self.exact_root or b"") != 32 or self.constraint is not None:
                raise ValueError("exact requirement must carry one 32-byte root")
        elif not self.logical_identity or self.constraint is None:
            raise ValueError("logical requirement needs nonempty identity and constraint")

    @classmethod
    def exact(cls, root: SemanticObject | bytes) -> "Requirement":
        return cls(exact_root=root.cid if isinstance(root, SemanticObject) else root)

    @classmethod
    def logical(cls, identity: bytes, constraint: VersionConstraint) -> "Requirement":
        return cls(logical_identity=identity, constraint=constraint)

    def key(self) -> bytes:
        if self.exact_root is not None:
            return b"\x01" + self.exact_root
        assert self.logical_identity is not None and self.constraint is not None
        return b"\x02" + _bytes(self.logical_identity) + self.constraint.encoded()

    def encoded(self) -> bytes:
        return self.key()


@dataclass(frozen=True)
class Candidate:
    package_root: bytes
    logical_identity: bytes
    version: Version
    dependencies: tuple[Requirement, ...] = ()

    def __post_init__(self) -> None:
        if len(self.package_root) != 32 or not self.logical_identity:
            raise ValueError("candidate requires exact root and logical identity")
        ordered = tuple(sorted(self.dependencies, key=Requirement.key))
        if ordered != self.dependencies or len(set(ordered)) != len(ordered):
            raise ValueError("candidate dependencies must be canonical sorted unique")


@dataclass(frozen=True)
class Catalog:
    entries: tuple[Candidate, ...]
    objects: Mapping[bytes, SemanticObject]

    def __post_init__(self) -> None:
        expected = tuple(sorted(self.entries, key=candidate_key))
        if expected != self.entries or len({item.package_root for item in self.entries}) != len(self.entries):
            raise ValueError("catalog entries must be canonical and roots unique")
        for entry in self.entries:
            obj = self.objects.get(entry.package_root)
            if obj is None or obj.kind != Kind.PACKAGE:
                raise ValueError("catalog root must name an available package object")
            if _package_identity(obj) != entry.logical_identity:
                raise ValueError("catalog logical identity disagrees with package semantics")

    @property
    def by_root(self) -> dict[bytes, Candidate]:
        return {item.package_root: item for item in self.entries}

    @property
    def by_identity(self) -> dict[bytes, tuple[Candidate, ...]]:
        grouped: dict[bytes, list[Candidate]] = {}
        for item in self.entries:
            grouped.setdefault(item.logical_identity, []).append(item)
        return {key: tuple(value) for key, value in grouped.items()}


@dataclass(frozen=True)
class ResolverLimits:
    max_states: int
    max_requirement_visits: int
    max_candidate_checks: int

    def __post_init__(self) -> None:
        if min(self.max_states, self.max_requirement_visits, self.max_candidate_checks) <= 0:
            raise ValueError("resolver limits must be positive")


DEFAULT_LIMITS = ResolverLimits(100_000, 1_000_000, 1_000_000)


@dataclass(frozen=True)
class ResolveStats:
    states: int
    requirement_visits: int
    candidate_checks: int
    backtracks: int

    @property
    def work_units(self) -> int:
        return self.states + self.requirement_visits + self.candidate_checks


@dataclass(frozen=True)
class Resolution:
    root: bytes
    selected_roots: tuple[bytes, ...]
    snapshot_bytes: bytes
    snapshot_digest: bytes
    catalog_digest: bytes
    stats: ResolveStats


@dataclass
class _MutableStats:
    states: int = 0
    requirement_visits: int = 0
    candidate_checks: int = 0
    backtracks: int = 0

    def frozen(self) -> ResolveStats:
        return ResolveStats(self.states, self.requirement_visits, self.candidate_checks, self.backtracks)


class _DeadEnd(Exception):
    pass


def _bytes(value: bytes) -> bytes:
    return uleb(len(value)) + value


def _package_identity(obj: SemanticObject) -> bytes:
    # Package body begins with canonical length-prefixed logical identity.
    data = memoryview(obj.body)
    value, used = _decode_uleb(data, 0)
    end = used + value
    if end > len(data):
        raise ValueError("truncated package logical identity")
    return bytes(data[used:end])


def _decode_uleb(data: memoryview, pos: int) -> tuple[int, int]:
    value = shift = 0
    start = pos
    for _ in range(10):
        if pos >= len(data):
            raise ValueError("truncated ULEB")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if byte == 0 and pos - start > 1:
                raise ValueError("non-minimal ULEB")
            return value, pos
        shift += 7
    raise ValueError("oversized ULEB")


def candidate_key(item: Candidate) -> tuple[bytes, Version, bytes]:
    return item.logical_identity, item.version, item.package_root


def canonical_candidate(root: bytes, identity: bytes, version: Version, dependencies: Iterable[Requirement] = ()) -> Candidate:
    return Candidate(root, identity, version, tuple(sorted(set(dependencies), key=Requirement.key)))


def encode_catalog(catalog: Catalog) -> bytes:
    out = bytearray(CATALOG_MAGIC + uleb(CATALOG_VERSION) + uleb(len(catalog.entries)))
    for item in catalog.entries:
        out.extend(item.package_root + _bytes(item.logical_identity) + item.version.encoded())
        out.extend(uleb(len(item.dependencies)))
        for requirement in item.dependencies:
            out.extend(requirement.encoded())
    payload = bytes(out)
    return payload + blake3(payload).digest()


def decode_catalog(data: bytes, objects: Mapping[bytes, SemanticObject]) -> Catalog:
    if len(data) < len(CATALOG_MAGIC) + 1 + 32 or not data.startswith(CATALOG_MAGIC):
        raise ValueError("invalid OI-23 catalog header")
    payload, stored_digest = data[:-32], data[-32:]
    if blake3(payload).digest() != stored_digest:
        raise ValueError("OI-23 catalog digest mismatch")
    view, pos = memoryview(payload), len(CATALOG_MAGIC)
    version, pos = _decode_uleb(view, pos)
    if version != CATALOG_VERSION:
        raise ValueError("unsupported OI-23 catalog version")
    count, pos = _decode_uleb(view, pos)
    entries: list[Candidate] = []

    def take(size: int) -> bytes:
        nonlocal pos
        if size < 0 or pos + size > len(view):
            raise ValueError("truncated OI-23 catalog")
        result = bytes(view[pos : pos + size])
        pos += size
        return result

    def read_bytes() -> bytes:
        nonlocal pos
        size, pos = _decode_uleb(view, pos)
        return take(size)

    def read_version() -> Version:
        nonlocal pos
        values = []
        for _ in range(3):
            value, pos = _decode_uleb(view, pos)
            values.append(value)
        return Version(*values)

    def read_requirement() -> Requirement:
        nonlocal pos
        form = take(1)[0]
        if form == 1:
            return Requirement.exact(take(32))
        if form != 2:
            raise ValueError("unknown OI-23 requirement form")
        logical = read_bytes()
        constraint_form = take(1)[0]
        if constraint_form == 1:
            constraint = VersionConstraint.exact_version(read_version())
        elif constraint_form == 2:
            constraint = VersionConstraint.range(read_version(), read_version())
        else:
            raise ValueError("unknown OI-23 constraint form")
        return Requirement.logical(logical, constraint)

    for _ in range(count):
        root, logical, ver = take(32), read_bytes(), read_version()
        dep_count, pos = _decode_uleb(view, pos)
        deps = tuple(read_requirement() for _ in range(dep_count))
        entries.append(Candidate(root, logical, ver, deps))
    if pos != len(view):
        raise ValueError("trailing OI-23 catalog bytes")
    catalog = Catalog(tuple(entries), objects)
    if encode_catalog(catalog) != data:
        raise ValueError("non-canonical OI-23 catalog")
    return catalog


def catalog_digest(catalog: Catalog) -> bytes:
    return blake3(encode_catalog(catalog)).digest()


def _snapshot(root: bytes, selected: Iterable[bytes], catalog_id: bytes) -> tuple[bytes, bytes]:
    roots = tuple(sorted(selected))
    payload = SNAPSHOT_MAGIC + uleb(SNAPSHOT_VERSION) + root + catalog_id + _bytes(RESOLVER_IDENTITY) + uleb(len(roots)) + b"".join(roots)
    return payload, blake3(payload).digest()


def _budget(stats: _MutableStats, limits: ResolverLimits, entity: bytes) -> None:
    if stats.states > limits.max_states:
        fail("XAX.RESOLVE.BUDGET", entity.hex(), "RESOLVE-STATE-BOUND", limits.max_states, stats.states)
    if stats.requirement_visits > limits.max_requirement_visits:
        fail("XAX.RESOLVE.BUDGET", entity.hex(), "RESOLVE-VISIT-BOUND", limits.max_requirement_visits, stats.requirement_visits)
    if stats.candidate_checks > limits.max_candidate_checks:
        fail("XAX.RESOLVE.BUDGET", entity.hex(), "RESOLVE-CANDIDATE-BOUND", limits.max_candidate_checks, stats.candidate_checks)


def _requirements(selected: Mapping[bytes, Candidate], stats: _MutableStats, limits: ResolverLimits, entity: bytes) -> tuple[Requirement, ...]:
    requirements: list[Requirement] = []
    for logical in sorted(selected):
        for requirement in selected[logical].dependencies:
            stats.requirement_visits += 1
            _budget(stats, limits, entity)
            requirements.append(requirement)
    return tuple(requirements)


def resolve(root: bytes, catalog: Catalog, limits: ResolverLimits = DEFAULT_LIMITS) -> Resolution:
    by_root, by_identity = catalog.by_root, catalog.by_identity
    if root not in by_root:
        fail("XAX.RESOLVE.MISSING", root.hex(), "RESOLVE-ROOT-PACKAGE", root.hex(), "missing")
    stats = _MutableStats()

    def search(selected: dict[bytes, Candidate]) -> dict[bytes, Candidate]:
        requirements = _requirements(selected, stats, limits, root)
        changed = True
        while changed:
            changed = False
            for requirement in requirements:
                if requirement.exact_root is None:
                    continue
                exact = by_root.get(requirement.exact_root)
                if exact is None:
                    raise _DeadEnd
                existing = selected.get(exact.logical_identity)
                if existing is not None and existing.package_root != exact.package_root:
                    raise _DeadEnd
                if existing is None:
                    selected = dict(selected)
                    selected[exact.logical_identity] = exact
                    stats.states += 1
                    _budget(stats, limits, root)
                    requirements = _requirements(selected, stats, limits, root)
                    changed = True
                    break

        constraints: dict[bytes, list[VersionConstraint]] = {}
        for requirement in requirements:
            if requirement.logical_identity is not None:
                assert requirement.constraint is not None
                constraints.setdefault(requirement.logical_identity, []).append(requirement.constraint)

        for identity, rules in constraints.items():
            existing = selected.get(identity)
            if existing is not None and not all(rule.allows(existing.version) for rule in rules):
                raise _DeadEnd

        unresolved = sorted(identity for identity in constraints if identity not in selected)
        if not unresolved:
            return selected
        identity = unresolved[0]
        rules = tuple(constraints[identity])
        compatible: list[Candidate] = []
        for item in reversed(by_identity.get(identity, ())):  # highest version/root order first
            stats.candidate_checks += 1
            _budget(stats, limits, root)
            if all(rule.allows(item.version) for rule in rules):
                compatible.append(item)
        if not compatible:
            raise _DeadEnd

        versions = sorted({item.version for item in compatible}, reverse=True)
        for version in versions:
            same_version = tuple(item for item in compatible if item.version == version)
            if len(same_version) > 1:
                fail(
                    "XAX.RESOLVE.AMBIGUOUS",
                    root.hex(),
                    "RESOLVE-VERSION-UNIQUE",
                    [identity.hex(), version.label(), "one exact root"],
                    [item.package_root.hex() for item in sorted(same_version, key=lambda item: item.package_root)],
                )
            item = same_version[0]
            stats.states += 1
            _budget(stats, limits, root)
            next_selected = dict(selected)
            next_selected[identity] = item
            try:
                return search(next_selected)
            except _DeadEnd:
                stats.backtracks += 1
        raise _DeadEnd

    start = by_root[root]
    try:
        selected = search({start.logical_identity: start})
    except _DeadEnd:
        frozen = stats.frozen()
        fail(
            "XAX.RESOLVE.UNSAT",
            root.hex(),
            "RESOLVE-CONSTRAINT-SATISFIABLE",
            "one exact compatible snapshot",
            {"states": frozen.states, "visits": frozen.requirement_visits, "checks": frozen.candidate_checks},
        )
    selected_roots = tuple(sorted(item.package_root for item in selected.values()))
    cat_digest = catalog_digest(catalog)
    snapshot_bytes, snapshot_digest = _snapshot(root, selected_roots, cat_digest)
    return Resolution(root, selected_roots, snapshot_bytes, snapshot_digest, cat_digest, stats.frozen())


def selected_versions(result: Resolution, catalog: Catalog) -> dict[str, str]:
    by_root = catalog.by_root
    return {
        by_root[root].logical_identity.decode("ascii", "backslashreplace"): by_root[root].version.label()
        for root in result.selected_roots
    }


def _semantic_package(identity: bytes, seed: int) -> tuple[SemanticObject, tuple[SemanticObject, ...]]:
    b32 = bits_type(32)
    value = constant(b32, seed & 0xFFFFFFFF)
    graph = graph_fragment((Block((), (Node(Operation.CONSTANT, (), (b32,), entity=value),), Terminator.return_((ValueRef.node_result(0, 0),))),))
    entry = function(graph, (), (b32,))
    module = object_with_refs(Kind.MODULE, (b32, value, entry))
    pkg = package(identity, (module,))
    return pkg, (b32, value, graph, entry, module, pkg)


def make_catalog(specs: Sequence[tuple[bytes, Version, Sequence[Requirement]]]) -> Catalog:
    objects: dict[bytes, SemanticObject] = {}
    entries = []
    for seed, (identity, version, dependencies) in enumerate(specs, 1):
        pkg, closure = _semantic_package(identity, seed * 2654435761)
        objects.update((item.cid, item) for item in closure)
        entries.append(canonical_candidate(pkg.cid, identity, version, dependencies))
    return Catalog(tuple(sorted(entries, key=candidate_key)), objects)


def add_dependency(catalog: Catalog, owner_root: bytes, requirement: Requirement) -> Catalog:
    entries = []
    for entry in catalog.entries:
        if entry.package_root == owner_root:
            entries.append(canonical_candidate(entry.package_root, entry.logical_identity, entry.version, (*entry.dependencies, requirement)))
        else:
            entries.append(entry)
    return Catalog(tuple(sorted(entries, key=candidate_key)), catalog.objects)


def replace_dependency(catalog: Catalog, owner_root: bytes, index: int, replacement: Requirement) -> Catalog:
    entries = []
    for entry in catalog.entries:
        if entry.package_root != owner_root:
            entries.append(entry)
            continue
        deps = list(entry.dependencies)
        if index < 0 or index >= len(deps):
            raise IndexError(index)
        deps[index] = replacement
        entries.append(canonical_candidate(entry.package_root, entry.logical_identity, entry.version, deps))
    return Catalog(tuple(sorted(entries, key=candidate_key)), catalog.objects)


def _candidate_root(catalog: Catalog, identity: bytes, version: Version) -> bytes:
    matches = [item.package_root for item in catalog.entries if item.logical_identity == identity and item.version == version]
    if len(matches) != 1:
        raise ValueError((identity, version, len(matches)))
    return matches[0]


def realistic_linear(versions: int = 6) -> tuple[Catalog, bytes]:
    specs: list[tuple[bytes, Version, Sequence[Requirement]]] = []
    for v in range(1, versions + 1):
        specs.append((b"util", Version(v), ()))
    for v in range(1, versions + 1):
        specs.append((b"lib", Version(v), (Requirement.logical(b"util", VersionConstraint.range(Version(max(1, v - 1)), Version(v + 2))),)))
    specs.append((b"app", Version(1), (Requirement.logical(b"lib", VersionConstraint.range(Version(2), Version(versions + 1))),)))
    catalog = make_catalog(specs)
    return catalog, _candidate_root(catalog, b"app", Version(1))


def realistic_diamond(versions: int = 8) -> tuple[Catalog, bytes]:
    specs: list[tuple[bytes, Version, Sequence[Requirement]]] = []
    for v in range(1, versions + 1):
        specs.append((b"shared", Version(v), ()))
    specs.extend(
        [
            (b"left", Version(1), (Requirement.logical(b"shared", VersionConstraint.range(Version(3), Version(7))),)),
            (b"right", Version(1), (Requirement.logical(b"shared", VersionConstraint.range(Version(5), Version(9))),)),
            (
                b"app",
                Version(1),
                (
                    Requirement.logical(b"left", VersionConstraint.exact_version(Version(1))),
                    Requirement.logical(b"right", VersionConstraint.exact_version(Version(1))),
                ),
            ),
        ]
    )
    catalog = make_catalog(specs)
    return catalog, _candidate_root(catalog, b"app", Version(1))


def realistic_major_coexistence() -> tuple[Catalog, bytes]:
    # Coexistence is explicit via distinct logical identities; one version per identity.
    specs = [
        (b"codec/1", Version(1, 4), ()),
        (b"codec/1", Version(1, 5), ()),
        (b"codec/2", Version(2, 0), ()),
        (b"codec/2", Version(2, 1), ()),
        (
            b"app",
            Version(1),
            (
                Requirement.logical(b"codec/1", VersionConstraint.range(Version(1, 0), Version(2, 0))),
                Requirement.logical(b"codec/2", VersionConstraint.range(Version(2, 0), Version(3, 0))),
            ),
        ),
    ]
    catalog = make_catalog(specs)
    return catalog, _candidate_root(catalog, b"app", Version(1))


def realistic_service(modules: int = 8, libraries: int = 4, versions: int = 6) -> tuple[Catalog, bytes]:
    specs: list[tuple[bytes, Version, Sequence[Requirement]]] = []
    for lib in range(libraries):
        identity = f"lib{lib}".encode()
        for v in range(1, versions + 1):
            deps: tuple[Requirement, ...] = ()
            if lib:
                prev = f"lib{lib - 1}".encode()
                deps = (Requirement.logical(prev, VersionConstraint.range(Version(max(1, v - 1)), Version(min(versions + 1, v + 2)))),)
            specs.append((identity, Version(v), deps))
    service_requirements = tuple(
        Requirement.logical(f"lib{i}".encode(), VersionConstraint.range(Version(2), Version(versions + 1)))
        for i in range(libraries)
    )
    for module in range(modules):
        specs.append((f"service/{module}".encode(), Version(1), service_requirements))
    specs.append(
        (
            b"app",
            Version(1),
            tuple(Requirement.logical(f"service/{module}".encode(), VersionConstraint.exact_version(Version(1))) for module in range(modules)),
        )
    )
    catalog = make_catalog(specs)
    return catalog, _candidate_root(catalog, b"app", Version(1))


def adversarial_backtrack(depth: int, versions: int) -> tuple[Catalog, bytes]:
    if depth < 2 or versions < 2:
        raise ValueError("adversarial fixture needs depth, versions >= 2")
    # Root chooses p0. Each p_i candidate forces the same version of p_(i+1).
    # At the leaf every version except 1 demands an unavailable exact root, so
    # descending search explores depth work for each rejected high version.
    specs: list[tuple[bytes, Version, Sequence[Requirement]]] = []
    roots_by_level: list[list[bytes]] = [[] for _ in range(depth)]
    pending: list[tuple[bytes, Version, Sequence[Requirement]]] = []
    # Build bottom-up so exact child roots are known.
    bottom_specs = []
    missing = bytes.fromhex("ff" * 32)
    for v in range(1, versions + 1):
        deps = () if v == 1 else (Requirement.exact(missing),)
        bottom_specs.append((f"p{depth - 1}".encode(), Version(v), deps))
    bottom = make_catalog(bottom_specs)
    all_entries = list(bottom.entries)
    all_objects = dict(bottom.objects)
    roots_by_level[-1] = [_candidate_root(bottom, f"p{depth - 1}".encode(), Version(v)) for v in range(1, versions + 1)]
    for level in range(depth - 2, -1, -1):
        local_specs = []
        for v in range(1, versions + 1):
            local_specs.append((f"p{level}".encode(), Version(v), (Requirement.exact(roots_by_level[level + 1][v - 1]),)))
        local = make_catalog(local_specs)
        all_entries.extend(local.entries)
        all_objects.update(local.objects)
        roots_by_level[level] = [_candidate_root(local, f"p{level}".encode(), Version(v)) for v in range(1, versions + 1)]
    root_pkg_catalog = make_catalog(((b"app", Version(1), (Requirement.logical(b"p0", VersionConstraint.range(Version(1), Version(versions + 1))),)),))
    all_entries.extend(root_pkg_catalog.entries)
    all_objects.update(root_pkg_catalog.objects)
    catalog = Catalog(tuple(sorted(all_entries, key=candidate_key)), all_objects)
    return catalog, _candidate_root(catalog, b"app", Version(1))


def ambiguous_fixture() -> tuple[Catalog, bytes]:
    first, first_closure = _semantic_package(b"lib", 100)
    second, second_closure = _semantic_package(b"lib", 101)
    app, app_closure = _semantic_package(b"app", 102)
    entries = (
        canonical_candidate(first.cid, b"lib", Version(2)),
        canonical_candidate(second.cid, b"lib", Version(2)),
        canonical_candidate(app.cid, b"app", Version(1), (Requirement.logical(b"lib", VersionConstraint.exact_version(Version(2))),)),
    )
    objects = {item.cid: item for item in (*first_closure, *second_closure, *app_closure)}
    catalog = Catalog(tuple(sorted(entries, key=candidate_key)), objects)
    return catalog, app.cid


def unsatisfied_fixture() -> tuple[Catalog, bytes]:
    specs = [
        (b"lib", Version(1), ()),
        (b"lib", Version(2), ()),
        (b"app", Version(1), (Requirement.logical(b"lib", VersionConstraint.range(Version(3), Version(4))),)),
    ]
    catalog = make_catalog(specs)
    return catalog, _candidate_root(catalog, b"app", Version(1))


def _diagnostic_bytes(error: XaxError) -> bytes:
    return json.dumps(
        {
            "code": error.diagnostic.code,
            "entity": error.diagnostic.entity,
            "rule": error.diagnostic.rule,
            "expected": error.diagnostic.expected,
            "actual": error.diagnostic.actual,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def encode_ai_add_view(owner: Candidate, logical_identity: bytes, candidates: Sequence[Candidate]) -> bytes:
    relevant = tuple(item for item in candidates if item.logical_identity == logical_identity)
    out = bytearray(b"A23Q" + uleb(AI_PACKET_VERSION) + owner.package_root + uleb(len(owner.dependencies)) + b"\x00" + _bytes(logical_identity))
    out.extend(uleb(len(relevant)))
    for item in sorted(relevant, key=candidate_key):
        out.extend(item.package_root + item.version.encoded())
    return bytes(out)


def encode_ai_view(owner: Candidate, candidates: Sequence[Candidate], dependency_index: int) -> bytes:
    if dependency_index >= len(owner.dependencies):
        raise IndexError(dependency_index)
    requirement = owner.dependencies[dependency_index]
    relevant = () if requirement.logical_identity is None else tuple(item for item in candidates if item.logical_identity == requirement.logical_identity)
    out = bytearray(b"A23Q" + uleb(AI_PACKET_VERSION) + owner.package_root + uleb(dependency_index) + requirement.encoded())
    out.extend(uleb(len(relevant)))
    for item in sorted(relevant, key=candidate_key):
        out.extend(item.package_root + item.version.encoded())
    return bytes(out)


def encode_ai_mutation(owner_root: bytes, dependency_index: int, requirement: Requirement) -> bytes:
    return b"A23M" + uleb(AI_PACKET_VERSION) + owner_root + uleb(dependency_index) + requirement.encoded()


def ai_tasks() -> tuple[dict[str, object], ...]:
    base, root = realistic_linear(5)
    app = base.by_root[root]
    changed = Requirement.logical(b"lib", VersionConstraint.range(Version(4), Version(6)))
    changed_catalog = replace_dependency(base, root, 0, changed)
    changed_result = resolve(root, changed_catalog)

    unsat, unsat_root = unsatisfied_fixture()
    unsat_owner = unsat.by_root[unsat_root]
    repair = Requirement.logical(b"lib", VersionConstraint.range(Version(2), Version(3)))
    repaired_unsat = replace_dependency(unsat, unsat_root, 0, repair)
    repair_result = resolve(unsat_root, repaired_unsat)

    ambiguous, ambiguous_root = ambiguous_fixture()
    ambiguous_owner = ambiguous.by_root[ambiguous_root]
    exact_choice = sorted((item for item in ambiguous.entries if item.logical_identity == b"lib"), key=lambda item: item.package_root)[0]
    exact_repair = Requirement.exact(exact_choice.package_root)
    repaired_ambiguous = replace_dependency(ambiguous, ambiguous_root, 0, exact_repair)
    exact_result = resolve(ambiguous_root, repaired_ambiguous)

    add_base = make_catalog(((b"lib", Version(1), ()), (b"app", Version(1), ())))
    add_root = _candidate_root(add_base, b"app", Version(1))
    add_owner = add_base.by_root[add_root]
    added_requirement = Requirement.logical(b"lib", VersionConstraint.range(Version(1), Version(2)))
    added_catalog = add_dependency(add_base, add_root, added_requirement)

    return (
        {
            "name": "add_dependency_constraint",
            "view_bytes": len(encode_ai_add_view(add_owner, b"lib", add_base.entries)),
            "mutation_bytes": len(encode_ai_mutation(add_root, 0, added_requirement)),
            "target_snapshot": resolve(add_root, added_catalog).snapshot_digest.hex(),
        },
        {
            "name": "change_dependency_range",
            "view_bytes": len(encode_ai_view(app, base.entries, 0)),
            "mutation_bytes": len(encode_ai_mutation(root, 0, changed)),
            "target_snapshot": changed_result.snapshot_digest.hex(),
        },
        {
            "name": "repair_unsatisfied_range",
            "view_bytes": len(encode_ai_view(unsat_owner, unsat.entries, 0)),
            "mutation_bytes": len(encode_ai_mutation(unsat_root, 0, repair)),
            "target_snapshot": repair_result.snapshot_digest.hex(),
        },
        {
            "name": "repair_ambiguous_with_exact_root",
            "view_bytes": len(encode_ai_view(ambiguous_owner, ambiguous.entries, 0)),
            "mutation_bytes": len(encode_ai_mutation(ambiguous_root, 0, exact_repair)),
            "target_snapshot": exact_result.snapshot_digest.hex(),
        },
    )


def corpus() -> dict[str, tuple[Catalog, bytes]]:
    return {
        "linear_upgrade": realistic_linear(),
        "diamond_shared": realistic_diamond(),
        "coexisting_major_lines": realistic_major_coexistence(),
        "generated_service": realistic_service(),
        "adversarial_d8_v4": adversarial_backtrack(8, 4),
        "adversarial_d16_v8": adversarial_backtrack(16, 8),
        "adversarial_d32_v8": adversarial_backtrack(32, 8),
    }


def _semantic_bytes(catalog: Catalog) -> int:
    return sum(len(obj.envelope()) for obj in catalog.objects.values())


def _resolution_record(name: str, catalog: Catalog, root: bytes) -> dict[str, object]:
    result = resolve(root, catalog)
    return {
        "name": name,
        "candidate_packages": len(catalog.entries),
        "semantic_objects": len(catalog.objects),
        "semantic_object_bytes": _semantic_bytes(catalog),
        "compatibility_catalog_bytes": len(encode_catalog(catalog)),
        "root": root.hex(),
        "snapshot": result.snapshot_digest.hex(),
        "selected_roots": [item.hex() for item in result.selected_roots],
        "selected_versions": selected_versions(result, catalog),
        "selected_count": len(result.selected_roots),
        "states": result.stats.states,
        "requirement_visits": result.stats.requirement_visits,
        "candidate_checks": result.stats.candidate_checks,
        "backtracks": result.stats.backtracks,
        "work_units": result.stats.work_units,
        "snapshot_bytes": len(result.snapshot_bytes),
    }


def _failure_record(catalog: Catalog, root: bytes) -> dict[str, object]:
    try:
        resolve(root, catalog)
    except XaxError as error:
        return {
            "code": error.diagnostic.code,
            "rule": error.diagnostic.rule,
            "diagnostic_bytes": len(_diagnostic_bytes(error)),
            "actual": error.diagnostic.actual,
        }
    raise AssertionError("fixture unexpectedly resolved")


def _measure_once(catalog: Catalog, root: bytes) -> int:
    start = time.perf_counter_ns()
    resolve(root, catalog)
    return time.perf_counter_ns() - start


def _host_identity() -> dict[str, object]:
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
    }


def measure(samples: int = 11) -> dict[str, object]:
    rows = []
    for name, (catalog, root) in corpus().items():
        # Warm Python/import paths but not semantic resolution state: resolver is pure/stateless.
        resolve(root, catalog)
        values = [_measure_once(catalog, root) for _ in range(samples)]
        rows.append({"name": name, "samples_ns": values})
    return {"schema": "xax-oi23-timing-v1", "host": _host_identity(), "samples": samples, "rows": rows}


def _summarize_timing(raw: Mapping[str, object]) -> dict[str, dict[str, float]]:
    result = {}
    for row in raw["rows"]:  # type: ignore[index]
        samples = list(row["samples_ns"])  # type: ignore[index]
        ordered = sorted(samples)
        result[row["name"]] = {  # type: ignore[index]
            "median_ms": statistics.median(samples) / 1e6,
            "min_ms": ordered[0] / 1e6,
            "max_ms": ordered[-1] / 1e6,
        }
    return result


def implementation_lines() -> dict[str, int]:
    resolver_lines = len(inspect.getsource(resolve).splitlines())
    codec_lines = len(inspect.getsource(encode_catalog).splitlines()) + len(inspect.getsource(decode_catalog).splitlines()) + len(inspect.getsource(VersionConstraint).splitlines())
    return {"resolver": resolver_lines, "constraint_and_catalog_codec": codec_lines}


def build_evidence(raw: Mapping[str, object]) -> dict[str, object]:
    records = [_resolution_record(name, cat, root) for name, (cat, root) in corpus().items()]
    ambiguous, ambiguous_root = ambiguous_fixture()
    unsat, unsat_root = unsatisfied_fixture()
    budget_cat, budget_root = adversarial_backtrack(16, 8)
    try:
        resolve(budget_root, budget_cat, ResolverLimits(3, 1_000_000, 1_000_000))
    except XaxError as error:
        budget_failure = {"code": error.diagnostic.code, "rule": error.diagnostic.rule, "actual": error.diagnostic.actual}
    else:
        raise AssertionError("state budget unexpectedly succeeded")

    tasks = list(ai_tasks())
    return {
        "schema": "xax-oi23-evidence-v1",
        "resolver_identity": RESOLVER_IDENTITY.decode(),
        "constraint_algebra": {
            "forms": ["exact_root", "exact_version", "inclusive_lower_exclusive_upper_range"],
            "selection": "highest compatible version; exact root authoritative",
            "coexistence": "one selected root per logical identity; simultaneous major lines use distinct logical identities",
            "excluded": ["OR", "arbitrary predicates", "scripts", "implicit latest"],
            "limits": {
                "states": DEFAULT_LIMITS.max_states,
                "requirement_visits": DEFAULT_LIMITS.max_requirement_visits,
                "candidate_checks": DEFAULT_LIMITS.max_candidate_checks,
            },
        },
        "workloads": records,
        "failures": {
            "ambiguous_same_version": _failure_record(ambiguous, ambiguous_root),
            "unsatisfied_range": _failure_record(unsat, unsat_root),
            "explicit_state_budget": budget_failure,
        },
        "implementation_lines": implementation_lines(),
        "timing": _summarize_timing(raw),
        "host_observation": raw["host"],
        "ai_mutation_tasks": tasks,
        "ai_model_measurement": {
            "available": False,
            "reason": "no OpenAI/Codex/Anthropic client, credentials, or tokenizer installed in measurement environment",
            "input_tokens": None,
            "output_tokens": None,
            "invalid_edits": None,
            "repair_turns": None,
        },
    }


def deterministic_projection(evidence: Mapping[str, object]) -> bytes:
    return json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--samples", type=int, default=11)
    parser.add_argument("--timing", type=Path, default=Path(__file__).with_name("oi23_package_resolver_timing.json"))
    parser.add_argument("--evidence", type=Path, default=Path(__file__).with_name("oi23_package_resolver_evidence.json"))
    args = parser.parse_args()
    if args.measure:
        raw = measure(args.samples)
        args.timing.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    else:
        raw = json.loads(args.timing.read_text())
    evidence = build_evidence(raw)
    args.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
