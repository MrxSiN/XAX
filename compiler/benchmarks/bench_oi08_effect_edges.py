"""OI-08 effect partition and persistent edge-encoding evidence.

This is a benchmark-only comparator.  It does not change the canonical XAX graph
or store schema.  Two candidate persistent effect sections are compared:

* explicit frontier: every event repeats each touched domain instance and its
  predecessor frontier;
* domain reconstruction: events are grouped by domain instance, with semantic
  topological runs and explicit predecessor deltas only where a run cannot imply
  the exact frontier (roots, forks, and joins remain explicit).

The compressed run order is part of the candidate effect section itself.  XAX
node/record serialization order is never consulted to infer an effect edge.
Timing samples are host observations and are not conformance thresholds.
"""
from __future__ import annotations

from dataclasses import dataclass
import heapq
import json
import platform
import statistics
import time
from pathlib import Path
from typing import Iterable, Sequence

from xax_compiler import (
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    _decode_function_interface,
    _parse_graph,
    bits_type,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    uleb,
    verify_store,
    write_store,
)

REPETITIONS = 31
ENCODING_REPETITIONS = 101
EXPLICIT_MAGIC = b"X8EF"
RECONSTRUCT_MAGIC = b"X8RC"

EffectKey = tuple[int, int]


class EffectEncodingError(ValueError):
    pass


@dataclass(frozen=True)
class EffectOrder:
    """Exact effect-domain footprint and predecessor frontier per event."""

    events: tuple[int, ...]
    footprints: tuple[tuple[int, tuple[EffectKey, ...]], ...]
    predecessors: tuple[tuple[int, EffectKey, tuple[int, ...]], ...]

    @classmethod
    def create(
        cls,
        events: Iterable[int],
        footprints: dict[int, Iterable[EffectKey]],
        predecessors: dict[tuple[int, EffectKey], Iterable[int]],
    ) -> "EffectOrder":
        event_tuple = tuple(sorted(set(events)))
        if not event_tuple or any(event < 1 for event in event_tuple):
            raise ValueError("effect event ids must be distinct positive integers")
        event_set = set(event_tuple)
        normalized_footprints: list[tuple[int, tuple[EffectKey, ...]]] = []
        normalized_predecessors: list[tuple[int, EffectKey, tuple[int, ...]]] = []
        for event in event_tuple:
            keys = tuple(sorted(set(footprints.get(event, ()))))
            if not keys:
                raise ValueError("every effect event must touch at least one domain instance")
            for domain, instance in keys:
                EffectDomain(domain)
                if instance < 0:
                    raise ValueError("effect instance must be nonnegative")
                preds = tuple(sorted(set(predecessors.get((event, (domain, instance)), ()))))
                if event in preds or any(pred not in event_set for pred in preds):
                    raise ValueError("effect predecessor must name another event")
                normalized_predecessors.append((event, (domain, instance), preds))
            normalized_footprints.append((event, keys))
        extra = set(predecessors) - {
            (event, key) for event, keys in normalized_footprints for key in keys
        }
        if extra:
            raise ValueError(f"predecessors supplied for absent footprint: {sorted(extra)}")
        order = cls(event_tuple, tuple(normalized_footprints), tuple(normalized_predecessors))
        order._validate()
        return order

    @classmethod
    def from_steps(cls, steps: Sequence[tuple[int, Sequence[EffectKey]]]) -> "EffectOrder":
        events: list[int] = []
        footprints: dict[int, tuple[EffectKey, ...]] = {}
        predecessors: dict[tuple[int, EffectKey], tuple[int, ...]] = {}
        last: dict[EffectKey, int] = {}
        for event, raw_keys in steps:
            if event in footprints:
                raise ValueError("duplicate event id")
            keys = tuple(sorted(set(raw_keys)))
            events.append(event)
            footprints[event] = keys
            for key in keys:
                predecessors[(event, key)] = () if key not in last else (last[key],)
                last[key] = event
        return cls.create(events, footprints, predecessors)

    def footprint_map(self) -> dict[int, tuple[EffectKey, ...]]:
        return dict(self.footprints)

    def predecessor_map(self) -> dict[tuple[int, EffectKey], tuple[int, ...]]:
        return {(event, key): preds for event, key, preds in self.predecessors}

    def keys(self) -> tuple[EffectKey, ...]:
        return tuple(sorted({key for _, keys in self.footprints for key in keys}))

    def direct_edges(self) -> frozenset[tuple[int, int]]:
        return frozenset(
            (pred, event)
            for event, _key, preds in self.predecessors
            for pred in preds
        )

    def _validate(self) -> None:
        footprint = self.footprint_map()
        predecessor = self.predecessor_map()
        members: dict[EffectKey, set[int]] = {key: set() for key in self.keys()}
        for event, keys in footprint.items():
            for key in keys:
                members[key].add(event)
        for (event, key), preds in predecessor.items():
            if event not in members[key] or any(pred not in members[key] for pred in preds):
                raise ValueError("effect predecessor must stay within one domain instance")
        self.topological_events()  # global cycle check

    def topological_events(self) -> tuple[int, ...]:
        outgoing: dict[int, set[int]] = {event: set() for event in self.events}
        indegree = {event: 0 for event in self.events}
        for source, target in self.direct_edges():
            if target not in outgoing[source]:
                outgoing[source].add(target)
                indegree[target] += 1
        ready = list(event for event in self.events if indegree[event] == 0)
        heapq.heapify(ready)
        result: list[int] = []
        while ready:
            event = heapq.heappop(ready)
            result.append(event)
            for target in sorted(outgoing[event]):
                indegree[target] -= 1
                if indegree[target] == 0:
                    heapq.heappush(ready, target)
        if len(result) != len(self.events):
            raise ValueError("effect partial order contains a cycle")
        return tuple(result)

    def domain_topological_events(self, key: EffectKey) -> tuple[int, ...]:
        members = {event for event, keys in self.footprints if key in keys}
        predecessor = self.predecessor_map()
        outgoing = {event: set() for event in members}
        indegree = {event: 0 for event in members}
        for event in members:
            for pred in predecessor[(event, key)]:
                if event not in outgoing[pred]:
                    outgoing[pred].add(event)
                    indegree[event] += 1
        ready = list(event for event in members if indegree[event] == 0)
        heapq.heapify(ready)
        result: list[int] = []
        while ready:
            event = heapq.heappop(ready)
            result.append(event)
            for target in sorted(outgoing[event]):
                indegree[target] -= 1
                if indegree[target] == 0:
                    heapq.heappush(ready, target)
        if len(result) != len(members):
            raise ValueError("per-domain effect partial order contains a cycle")
        return tuple(result)

    def coarsen(self) -> "EffectOrder":
        """Conservatively collapse every proven instance to domain instance zero."""
        steps = []
        footprints = self.footprint_map()
        for event in self.topological_events():
            steps.append((event, tuple(sorted({(domain, 0) for domain, _ in footprints[event]}))))
        return EffectOrder.from_steps(steps)


def _closure(order: EffectOrder) -> dict[int, frozenset[int]]:
    outgoing: dict[int, set[int]] = {event: set() for event in order.events}
    for source, target in order.direct_edges():
        outgoing[source].add(target)
    closure: dict[int, frozenset[int]] = {}
    for event in order.events:
        seen: set[int] = set()
        stack = list(outgoing[event])
        while stack:
            item = stack.pop()
            if item in seen:
                continue
            seen.add(item)
            stack.extend(outgoing[item] - seen)
        closure[event] = frozenset(seen)
    return closure


def order_metrics(order: EffectOrder) -> dict:
    closure = _closure(order)
    comparable = sum(len(targets) for targets in closure.values())
    total_pairs = len(order.events) * (len(order.events) - 1) // 2
    topological = order.topological_events()
    longest: dict[int, int] = {event: 1 for event in topological}
    incoming: dict[int, list[int]] = {event: [] for event in topological}
    for source, target in order.direct_edges():
        incoming[target].append(source)
    for event in topological:
        if incoming[event]:
            longest[event] = 1 + max(longest[pred] for pred in incoming[event])
    return {
        "event_count": len(order.events),
        "domain_instance_count": len(order.keys()),
        "direct_edge_count": len(order.direct_edges()),
        "closure_edge_count": comparable,
        "unordered_pairs": total_pairs - comparable,
        "unordered_pair_fraction": 0.0 if not total_pairs else (total_pairs - comparable) / total_pairs,
        "critical_path_events": max(longest.values()),
    }


def _common_prefix(magic: bytes, order: EffectOrder) -> tuple[bytearray, dict[int, int], dict[EffectKey, int], int]:
    events = order.events
    keys = order.keys()
    event_index = {event: i for i, event in enumerate(events)}
    key_index = {key: i for i, key in enumerate(keys)}
    out = bytearray(magic)
    atoms = 0
    out += uleb(len(events)); atoms += 1
    for event in events:
        out += uleb(event); atoms += 1
    out += uleb(len(keys)); atoms += 1
    for domain, instance in keys:
        out += uleb(domain) + uleb(instance); atoms += 2
    return out, event_index, key_index, atoms


def encode_explicit_frontier(order: EffectOrder) -> tuple[bytes, int]:
    out, event_index, key_index, atoms = _common_prefix(EXPLICIT_MAGIC, order)
    footprints = order.footprint_map()
    predecessors = order.predecessor_map()
    for event in order.events:
        keys = footprints[event]
        out += uleb(len(keys)); atoms += 1
        for key in keys:
            preds = predecessors[(event, key)]
            out += uleb(key_index[key]) + uleb(len(preds)); atoms += 2
            for pred in preds:
                out += uleb(event_index[pred]); atoms += 1
    return bytes(out), atoms


def encode_reconstructed(order: EffectOrder) -> tuple[bytes, int]:
    out, event_index, _key_index, atoms = _common_prefix(RECONSTRUCT_MAGIC, order)
    predecessors = order.predecessor_map()
    for key in order.keys():
        members = order.domain_topological_events(key)
        positions = {event: i for i, event in enumerate(members)}
        out += uleb(len(members)); atoms += 1
        for event in members:
            out += uleb(event_index[event]); atoms += 1
        for i, event in enumerate(members):
            pred_positions = tuple(sorted(positions[pred] for pred in predecessors[(event, key)]))
            if not pred_positions:
                out += uleb(0); atoms += 1
            elif len(pred_positions) == 1 and pred_positions[0] == i - 1:
                out += uleb(1); atoms += 1
            else:
                out += uleb(2 + len(pred_positions)); atoms += 1
                for pred_pos in pred_positions:
                    distance = i - pred_pos
                    if distance <= 0:
                        raise ValueError("predecessor must precede event in domain topological order")
                    out += uleb(distance); atoms += 1
    return bytes(out), atoms


class _Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        if self.pos + count > len(self.data):
            raise EffectEncodingError("truncated effect encoding")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def integer(self) -> int:
        start = self.pos
        value = 0
        shift = 0
        while True:
            if self.pos >= len(self.data) or shift > 63:
                raise EffectEncodingError("invalid ULEB128")
            byte = self.data[self.pos]
            self.pos += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        if self.data[start:self.pos] != uleb(value):
            raise EffectEncodingError("non-canonical ULEB128")
        return value

    def end(self) -> None:
        if self.pos != len(self.data):
            raise EffectEncodingError("trailing effect encoding bytes")


def _decode_common(data: bytes, magic: bytes) -> tuple[_Cursor, tuple[int, ...], tuple[EffectKey, ...]]:
    cursor = _Cursor(data)
    if cursor.take(4) != magic:
        raise EffectEncodingError("wrong effect encoding magic")
    event_count = cursor.integer()
    events = tuple(cursor.integer() for _ in range(event_count))
    if not events or tuple(sorted(set(events))) != events or events[0] < 1:
        raise EffectEncodingError("event table must be sorted unique positive ids")
    key_count = cursor.integer()
    keys = tuple((cursor.integer(), cursor.integer()) for _ in range(key_count))
    try:
        for domain, instance in keys:
            EffectDomain(domain)
            if instance < 0:
                raise EffectEncodingError("negative effect instance")
    except ValueError as error:
        raise EffectEncodingError("unknown effect domain") from error
    if not keys or tuple(sorted(set(keys))) != keys:
        raise EffectEncodingError("domain-instance table must be sorted and unique")
    return cursor, events, keys


def decode_explicit_frontier(data: bytes) -> EffectOrder:
    cursor, events, keys = _decode_common(data, EXPLICIT_MAGIC)
    footprints: dict[int, tuple[EffectKey, ...]] = {}
    predecessors: dict[tuple[int, EffectKey], tuple[int, ...]] = {}
    for event in events:
        count = cursor.integer()
        domain_indices: list[int] = []
        for _ in range(count):
            domain_index = cursor.integer()
            if domain_index >= len(keys):
                raise EffectEncodingError("domain index out of range")
            pred_count = cursor.integer()
            pred_indices = tuple(cursor.integer() for _ in range(pred_count))
            if any(index >= len(events) for index in pred_indices):
                raise EffectEncodingError("predecessor index out of range")
            if tuple(sorted(set(pred_indices))) != pred_indices:
                raise EffectEncodingError("predecessor indices must be canonical")
            domain_indices.append(domain_index)
            predecessors[(event, keys[domain_index])] = tuple(events[index] for index in pred_indices)
        if not domain_indices or domain_indices != sorted(set(domain_indices)):
            raise EffectEncodingError("event domain indices must be sorted unique and nonempty")
        footprints[event] = tuple(keys[index] for index in domain_indices)
    cursor.end()
    try:
        order = EffectOrder.create(events, footprints, predecessors)
    except ValueError as error:
        raise EffectEncodingError(str(error)) from error
    if order.keys() != keys:
        raise EffectEncodingError("unused domain-instance table entry")
    return order


def decode_reconstructed(data: bytes) -> EffectOrder:
    cursor, events, keys = _decode_common(data, RECONSTRUCT_MAGIC)
    event_by_index = events
    footprints: dict[int, list[EffectKey]] = {event: [] for event in events}
    predecessors: dict[tuple[int, EffectKey], tuple[int, ...]] = {}
    for key in keys:
        count = cursor.integer()
        member_indices = tuple(cursor.integer() for _ in range(count))
        if not member_indices or any(index >= len(events) for index in member_indices) or len(set(member_indices)) != len(member_indices):
            raise EffectEncodingError("domain member list must be nonempty, unique, and in range")
        members = tuple(event_by_index[index] for index in member_indices)
        for event in members:
            footprints[event].append(key)
        for i, event in enumerate(members):
            code = cursor.integer()
            if code == 0:
                preds: tuple[int, ...] = ()
            elif code == 1:
                if i == 0:
                    raise EffectEncodingError("previous-member predecessor on first domain event")
                preds = (members[i - 1],)
            else:
                pred_count = code - 2
                if pred_count < 1:
                    raise EffectEncodingError("non-canonical predecessor code")
                distances = tuple(cursor.integer() for _ in range(pred_count))
                if any(distance < 1 or distance > i for distance in distances):
                    raise EffectEncodingError("predecessor distance out of range")
                pred_positions = tuple(i - distance for distance in distances)
                if tuple(sorted(set(pred_positions))) != pred_positions:
                    raise EffectEncodingError("predecessors must be canonical by domain position")
                if len(pred_positions) == 1 and pred_positions[0] == i - 1:
                    raise EffectEncodingError("previous predecessor must use compact code")
                preds = tuple(members[position] for position in pred_positions)
            predecessors[(event, key)] = preds
    cursor.end()
    if any(not keys_ for keys_ in footprints.values()):
        raise EffectEncodingError("event absent from all domain-instance sections")
    try:
        order = EffectOrder.create(events, footprints, predecessors)
    except ValueError as error:
        raise EffectEncodingError(str(error)) from error
    if order.keys() != keys:
        raise EffectEncodingError("unused domain-instance table entry")
    return order


def verify_candidate(data: bytes, expected: EffectOrder) -> EffectOrder:
    if data.startswith(EXPLICIT_MAGIC):
        actual = decode_explicit_frontier(data)
    elif data.startswith(RECONSTRUCT_MAGIC):
        actual = decode_reconstructed(data)
    else:
        raise EffectEncodingError("unknown effect encoding")
    if actual != expected:
        raise EffectEncodingError("reconstructed effect frontier differs from authoritative partial order")
    if _closure(actual) != _closure(expected):
        raise EffectEncodingError("reconstructed effect partial order differs from authoritative partial order")
    return actual


def _pack(objects, graph, entry):
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*objects, graph, entry, module, root)))
    return reader, entry, graph


def linear_fixture(order: EffectOrder):
    effect_objects = {key: effect_type(EffectDomain(key[0]), key[1]) for key in order.keys()}
    key_order = order.keys()
    current = {key: ValueRef.parameter(0, index) for index, key in enumerate(key_order)}
    node_by_event: dict[int, int] = {}
    nodes: list[Node] = []
    footprint = order.footprint_map()
    predecessor = order.predecessor_map()
    # This builder accepts the straight/multi-domain workloads where each domain
    # event has at most one predecessor. Branch/merge is built separately below.
    if any(len(preds) > 1 for preds in predecessor.values()):
        raise ValueError("linear fixture cannot represent a join frontier")
    for event in order.topological_events():
        keys = footprint[event]
        expected_preds = {pred for key in keys for pred in predecessor[(event, key)]}
        # current refs embody the exact per-domain predecessors; no unrelated
        # topological position becomes an effect dependency.
        operands = tuple(current[key] for key in keys)
        node_index = len(nodes)
        nodes.append(Node(Operation.EFFECT_STEP, operands, tuple(effect_objects[key] for key in keys)))
        node_by_event[event] = node_index
        for result_index, key in enumerate(keys):
            current[key] = ValueRef.node_result(0, node_index, result_index)
        # Sanity check the semantic predecessor relation against the refs chosen.
        for key, operand in zip(keys, operands):
            preds = predecessor[(event, key)]
            if preds:
                pred = preds[0]
                if operand != ValueRef.node_result(0, node_by_event[pred], footprint[pred].index(key)):
                    raise AssertionError("builder changed effect predecessor")
            elif operand.tag != 0:
                raise AssertionError("root effect event did not consume block frontier")
        del expected_preds
    returns = tuple(current[key] for key in key_order)
    parameters = tuple(effect_objects[key] for key in key_order)
    graph = graph_fragment((Block(parameters, tuple(nodes), Terminator.return_(returns)),))
    entry = function(graph, parameters, parameters)
    return _pack(tuple(effect_objects.values()), graph, entry)


def branch_order() -> EffectOrder:
    key = (int(EffectDomain.FILESYSTEM), 1)
    events = (17, 3, 29)
    return EffectOrder.create(
        events,
        {17: (key,), 3: (key,), 29: (key,)},
        {(17, key): (), (3, key): (), (29, key): (3, 17)},
    )


def branch_fixture():
    b1 = bits_type(1)
    effect = effect_type(EffectDomain.FILESYSTEM, 1)
    blocks = (
        Block(
            (b1, effect),
            (),
            Terminator.conditional_branch(
                ValueRef.parameter(0, 0),
                1,
                (ValueRef.parameter(0, 1),),
                2,
                (ValueRef.parameter(0, 1),),
            ),
        ),
        Block(
            (effect,),
            (Node(Operation.EFFECT_STEP, (ValueRef.parameter(1, 0),), (effect,)),),
            Terminator.branch(3, (ValueRef.node_result(1, 0, 0),)),
        ),
        Block(
            (effect,),
            (Node(Operation.EFFECT_STEP, (ValueRef.parameter(2, 0),), (effect,)),),
            Terminator.branch(3, (ValueRef.node_result(2, 0, 0),)),
        ),
        Block(
            (effect,),
            (Node(Operation.EFFECT_STEP, (ValueRef.parameter(3, 0),), (effect,)),),
            Terminator.return_((ValueRef.node_result(3, 0, 0),)),
        ),
    )
    graph = graph_fragment(blocks)
    entry = function(graph, (b1, effect), (effect,))
    return _pack((b1, effect), graph, entry)


def pair_order(domain: EffectDomain) -> EffectOrder:
    ids = (41, 7, 88, 13, 55, 2, 79, 23)
    steps = []
    for index, event in enumerate(ids):
        steps.append((event, ((int(domain), 1 if index % 2 == 0 else 2),)))
    return EffectOrder.from_steps(steps)


def mixed_order() -> EffectOrder:
    ids = tuple(((index * 17) % 37) for index in range(1, 37))
    keys = {
        "m1": (int(EffectDomain.MEMORY), 1), "m2": (int(EffectDomain.MEMORY), 2),
        "f1": (int(EffectDomain.FILESYSTEM), 1), "f2": (int(EffectDomain.FILESYSTEM), 2),
        "n1": (int(EffectDomain.NETWORK), 1), "n2": (int(EffectDomain.NETWORK), 2),
        "d1": (int(EffectDomain.DEVICE), 1), "d2": (int(EffectDomain.DEVICE), 2),
    }
    pattern = (
        (keys["m1"],), (keys["m2"],), (keys["f1"],), (keys["f2"],),
        (keys["n1"],), (keys["n2"],), (keys["d1"],), (keys["d2"],),
        (keys["m1"], keys["d1"]), (keys["m2"], keys["d2"]),
        (keys["f1"], keys["n1"]), (keys["f2"], keys["n2"]),
    )
    return EffectOrder.from_steps(tuple((event, pattern[index % len(pattern)]) for index, event in enumerate(ids)))


def token_atoms(reader: StoreReader, entry) -> int:
    objects = {obj.cid: obj for obj in reader.objects()}
    resolve = objects.__getitem__
    graph_obj, _, _ = _decode_function_interface(entry, resolve)
    graph = _parse_graph(graph_obj, resolve)
    total = 0
    for block in graph.blocks:
        total += 1 + len(block.parameters)
        for node in block.nodes:
            total += 1 + len(node.operands) + len(node.results) + len(node.attributes)
            total += 1 if node.entity is not None else 0
            total += 1 if node.member is not None else 0
        total += 1 + len(block.terminator.values) + sum(1 + len(args) for _, args in block.terminator.edges)
    return total


def _timing_summary_ns(samples: Sequence[int]) -> dict:
    return {
        "raw_ns": list(samples),
        "min_ns": min(samples),
        "median_ns": int(statistics.median(samples)),
        "max_ns": max(samples),
    }


def _measure(callable_, repetitions: int) -> dict:
    samples = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        callable_()
        samples.append(time.perf_counter_ns() - start)
    return _timing_summary_ns(samples)


def graph_measurement(order: EffectOrder, fixture=linear_fixture) -> dict:
    reader, entry, graph = fixture(order) if fixture is linear_fixture else fixture()
    verify_store(reader)
    data = reader.canonical_bytes()
    return {
        "root_cid": reader.root_cid.hex(),
        "graph_cid": graph.cid.hex(),
        "graph_body_bytes": len(graph.body),
        "graph_envelope_bytes": len(graph.envelope()),
        "store_bytes": len(data),
        "token_atoms": token_atoms(reader, entry),
        "verify_time": _measure(lambda: verify_store(StoreReader(data)), REPETITIONS),
    }


def encoding_measurement(order: EffectOrder) -> dict:
    explicit, explicit_atoms = encode_explicit_frontier(order)
    reconstructed, reconstructed_atoms = encode_reconstructed(order)
    verify_candidate(explicit, order)
    verify_candidate(reconstructed, order)
    return {
        "explicit_frontier": {
            "bytes": len(explicit),
            "token_atoms": explicit_atoms,
            "verify_time": _measure(lambda: verify_candidate(explicit, order), ENCODING_REPETITIONS),
        },
        "domain_reconstruction": {
            "bytes": len(reconstructed),
            "token_atoms": reconstructed_atoms,
            "verify_time": _measure(lambda: verify_candidate(reconstructed, order), ENCODING_REPETITIONS),
            "reconstruction_time": _measure(lambda: decode_reconstructed(reconstructed), ENCODING_REPETITIONS),
        },
        "byte_delta": len(reconstructed) - len(explicit),
        "byte_percent": (len(reconstructed) - len(explicit)) * 100.0 / len(explicit),
        "token_atom_delta": reconstructed_atoms - explicit_atoms,
        "token_atom_percent": (reconstructed_atoms - explicit_atoms) * 100.0 / explicit_atoms,
        "partial_order_identical": _closure(decode_explicit_frontier(explicit)) == _closure(decode_reconstructed(reconstructed)) == _closure(order),
    }


def _deterministic_encoding_fields(measurement: dict) -> dict:
    return {
        "explicit_frontier_bytes": measurement["explicit_frontier"]["bytes"],
        "explicit_frontier_token_atoms": measurement["explicit_frontier"]["token_atoms"],
        "domain_reconstruction_bytes": measurement["domain_reconstruction"]["bytes"],
        "domain_reconstruction_token_atoms": measurement["domain_reconstruction"]["token_atoms"],
        "byte_delta": measurement["byte_delta"],
        "token_atom_delta": measurement["token_atom_delta"],
        "partial_order_identical": measurement["partial_order_identical"],
    }


def collect_evidence() -> dict:
    workloads: dict[str, dict] = {}
    for name, domain in (
        ("memory_pair", EffectDomain.MEMORY),
        ("filesystem_pair", EffectDomain.FILESYSTEM),
        ("network_pair", EffectDomain.NETWORK),
        ("device_pair", EffectDomain.DEVICE),
    ):
        refined = pair_order(domain)
        coarse = refined.coarsen()
        workloads[name] = {
            "refined": {
                "partial_order": order_metrics(refined),
                "graph": graph_measurement(refined),
                "encoding": encoding_measurement(refined),
            },
            "coarse": {
                "partial_order": order_metrics(coarse),
                "graph": graph_measurement(coarse),
                "encoding": encoding_measurement(coarse),
            },
        }
    refined = mixed_order()
    coarse = refined.coarsen()
    workloads["mixed_four_domain"] = {
        "refined": {
            "partial_order": order_metrics(refined),
            "graph": graph_measurement(refined),
            "encoding": encoding_measurement(refined),
        },
        "coarse": {
            "partial_order": order_metrics(coarse),
            "graph": graph_measurement(coarse),
            "encoding": encoding_measurement(coarse),
        },
    }
    branch = branch_order()
    workloads["filesystem_branch_merge"] = {
        "refined": {
            "partial_order": order_metrics(branch),
            "graph": graph_measurement(branch, branch_fixture),
            "encoding": encoding_measurement(branch),
        }
    }

    partition_summary = {}
    for name, row in workloads.items():
        if "coarse" not in row:
            continue
        refined_metrics = row["refined"]["partial_order"]
        coarse_metrics = row["coarse"]["partial_order"]
        partition_summary[name] = {
            "additional_unordered_pairs": refined_metrics["unordered_pairs"] - coarse_metrics["unordered_pairs"],
            "critical_path_reduction_events": coarse_metrics["critical_path_events"] - refined_metrics["critical_path_events"],
            "graph_body_byte_cost": row["refined"]["graph"]["graph_body_bytes"] - row["coarse"]["graph"]["graph_body_bytes"],
            "graph_token_atom_cost": row["refined"]["graph"]["token_atoms"] - row["coarse"]["graph"]["token_atoms"],
        }

    encoding_summary = {
        name: _deterministic_encoding_fields(row["refined"]["encoding"])
        for name, row in workloads.items()
    }

    return {
        "schema": "xax.oi08-effect-edges.v1",
        "host": {"python": platform.python_version(), "platform": platform.platform()},
        "repetitions": {"store_verify": REPETITIONS, "encoding": ENCODING_REPETITIONS},
        "token_metric": "ideal token-native semantic scalar/handle atoms; not a text tokenizer",
        "workloads": workloads,
        "partition_summary": partition_summary,
        "encoding_summary": encoding_summary,
        "claims": {
            "partition_policy": "partition memory/filesystem/network/device only by verifier-proven independent domain instance; instance 0 remains the conservative fallback when independence is unproven",
            "persistent_candidate": "domain-grouped reconstruction preserves exact predecessor frontiers while omitting repeated domain/predecessor handles on common linear runs",
            "serialization_order": "candidate reconstruction uses explicit operation handles plus semantic per-domain run order and predecessor deltas; ordinary graph/store record order is never consulted",
            "branching": "filesystem_branch_merge exercises two roots and a two-predecessor join so compression is not limited to total chains",
            "canonical_status": "benchmark only; neither candidate changes the canonical XAX graph/store schema in OI-08",
        },
    }


def main() -> None:
    evidence = collect_evidence()
    output = Path(__file__).with_name("oi08_effect_edges_evidence.json")
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
