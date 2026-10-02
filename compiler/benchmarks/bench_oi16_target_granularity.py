"""OI-16 target-contract granularity and opaque-minimum evidence.

All schemas in this file are measurement-only.  They do not replace canonical
XAX target packages or backend bootstrap tables.  Both candidate forms decode
to the same complete semantic contract set before the existing backends are
invoked.
"""

from __future__ import annotations

import copy
import inspect
import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from blake3 import blake3

from xax_aarch64 import compile_aarch64
from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    aarch64_baremetal_target,
    bits_type,
    execute,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    wasm32_target,
    write_store,
    x86_64_windows_target,
)
from xax_wasm import compile_wasm, run_wasm_isolated
from xax_x86_64 import compile_native


HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "oi16_target_granularity_evidence.json"
TIMING = HERE / "oi16_target_granularity_timing.json"
MAGIC = b"XOI16\x01"


class PackageError(ValueError):
    pass


@dataclass(frozen=True)
class Contract:
    semantic_operation: int
    widths: tuple[int, ...]
    input_arity: int
    output_arity: int
    effects: int
    control: int
    memory: int
    optimization: int


@dataclass(frozen=True)
class Variant:
    semantic_operation: int
    width: int
    encoding_variant: int


@dataclass(frozen=True)
class DecodedPackage:
    form: str
    target: str
    contracts: tuple[Contract, ...]
    variants: tuple[Variant, ...]


# Complete contract fields for this pure arithmetic family.  Zero means an
# explicit empty behavior, not an omitted/unknown field.
PURE_EFFECTS = 0
NO_CONTROL = 0
NO_MEMORY = 0
OPT_PURE_FOLD_CSE_REORDER = 0b111
ARITHMETIC_OPS = (Operation.ADD_WRAP.value, Operation.SUB_WRAP.value)
WIDTHS = (32, 64)

TARGETS = {
    "x86_64_windows": {
        "target": x86_64_windows_target,
        "compile": compile_native,
        "variant_base": 0x100,
    },
    "aarch64_baremetal": {
        "target": aarch64_baremetal_target,
        "compile": compile_aarch64,
        "variant_base": 0x200,
    },
    "wasm32_core": {
        "target": wasm32_target,
        "compile": compile_wasm,
        "variant_base": 0x300,
    },
}


def _u(value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned measurement field must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _take_u(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    shift = 0
    start = position
    while position < len(data):
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if _u(value) != data[start:position]:
                raise PackageError("noncanonical integer")
            return value, position
        shift += 7
        if shift > 63:
            break
    raise PackageError("malformed integer")


def _frame(form: int, target: str, body: bytes) -> bytes:
    target_bytes = target.encode("ascii")
    prefix = MAGIC + bytes((form,)) + _u(len(target_bytes)) + target_bytes + _u(len(body)) + body
    return prefix + blake3(prefix).digest()


def encode_per_instruction(target: str) -> bytes:
    """Full semantic contract repeated for each target instruction variant."""
    records = bytearray()
    base = TARGETS[target]["variant_base"]
    records.extend(_u(len(ARITHMETIC_OPS) * len(WIDTHS)))
    for op_index, operation in enumerate(ARITHMETIC_OPS):
        for width_index, width in enumerate(WIDTHS):
            encoding = base + op_index * 16 + width_index
            # semantic op, exact type width/arity, explicit effects/control/
            # memory/optimization restrictions, target encoding variant.
            for value in (
                operation, width, 2, width, width, 1, width,
                PURE_EFFECTS, NO_CONTROL, NO_MEMORY,
                OPT_PURE_FOLD_CSE_REORDER, encoding,
            ):
                records.extend(_u(value))
    return _frame(1, target, bytes(records))


def encode_shared_primitives(target: str) -> bytes:
    """Semantic primitives are shared; target encodings are separate variants."""
    body = bytearray()
    body.extend(_u(len(ARITHMETIC_OPS)))
    for operation in ARITHMETIC_OPS:
        body.extend(_u(operation))
        body.extend(_u(2) + _u(1))  # arity
        body.extend(_u(len(WIDTHS)) + b"".join(_u(width) for width in WIDTHS))
        body.extend(_u(PURE_EFFECTS) + _u(NO_CONTROL) + _u(NO_MEMORY) + _u(OPT_PURE_FOLD_CSE_REORDER))
    variants: list[tuple[int, int, int]] = []
    base = TARGETS[target]["variant_base"]
    for primitive_index, _operation in enumerate(ARITHMETIC_OPS):
        for width_index, width in enumerate(WIDTHS):
            variants.append((primitive_index, width, base + primitive_index * 16 + width_index))
    body.extend(_u(len(variants)))
    for primitive_index, width, encoding in variants:
        body.extend(_u(primitive_index) + _u(width) + _u(encoding))
    return _frame(2, target, bytes(body))


def _open(payload: bytes, expected_form: int) -> tuple[str, bytes]:
    if len(payload) < len(MAGIC) + 1 + 32 or payload[: len(MAGIC)] != MAGIC:
        raise PackageError("wrong package magic/version")
    if payload[len(MAGIC)] != expected_form:
        raise PackageError("wrong package form")
    prefix, digest = payload[:-32], payload[-32:]
    if blake3(prefix).digest() != digest:
        raise PackageError("package digest mismatch")
    position = len(MAGIC) + 1
    name_length, position = _take_u(prefix, position)
    end = position + name_length
    if end > len(prefix):
        raise PackageError("target name truncated")
    try:
        target = prefix[position:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise PackageError("target name is not ASCII") from error
    if target not in TARGETS:
        raise PackageError("unknown target")
    position = end
    body_length, position = _take_u(prefix, position)
    if position + body_length != len(prefix):
        raise PackageError("package body length mismatch")
    return target, prefix[position:]


def decode_per_instruction(payload: bytes) -> DecodedPackage:
    target, body = _open(payload, 1)
    position = 0
    count, position = _take_u(body, position)
    contracts: list[Contract] = []
    variants: list[Variant] = []
    seen: set[tuple[int, int]] = set()
    for _ in range(count):
        fields = []
        for _field in range(12):
            value, position = _take_u(body, position)
            fields.append(value)
        operation, width, in_arity, in0, in1, out_arity, out0, effects, control, memory, optimization, encoding = fields
        if in_arity != 2 or out_arity != 1 or (in0, in1, out0) != (width, width, width):
            raise PackageError("instruction type contract mismatch")
        key = (operation, width)
        if key in seen:
            raise PackageError("duplicate instruction contract")
        seen.add(key)
        contracts.append(Contract(operation, (width,), in_arity, out_arity, effects, control, memory, optimization))
        variants.append(Variant(operation, width, encoding))
    if position != len(body):
        raise PackageError("trailing package bytes")
    return _validated(DecodedPackage("per_instruction", target, tuple(contracts), tuple(variants)))


def decode_shared_primitives(payload: bytes) -> DecodedPackage:
    target, body = _open(payload, 2)
    position = 0
    primitive_count, position = _take_u(body, position)
    contracts: list[Contract] = []
    for _ in range(primitive_count):
        operation, position = _take_u(body, position)
        in_arity, position = _take_u(body, position)
        out_arity, position = _take_u(body, position)
        width_count, position = _take_u(body, position)
        widths = []
        for _width in range(width_count):
            value, position = _take_u(body, position)
            widths.append(value)
        effects, position = _take_u(body, position)
        control, position = _take_u(body, position)
        memory, position = _take_u(body, position)
        optimization, position = _take_u(body, position)
        contracts.append(Contract(operation, tuple(widths), in_arity, out_arity, effects, control, memory, optimization))
    variant_count, position = _take_u(body, position)
    variants = []
    seen: set[tuple[int, int]] = set()
    for _ in range(variant_count):
        primitive_index, position = _take_u(body, position)
        width, position = _take_u(body, position)
        encoding, position = _take_u(body, position)
        if primitive_index >= len(contracts):
            raise PackageError("variant references missing primitive")
        primitive = contracts[primitive_index]
        if width not in primitive.widths:
            raise PackageError("variant width outside primitive legality")
        key = (primitive.semantic_operation, width)
        if key in seen:
            raise PackageError("duplicate encoding variant")
        seen.add(key)
        variants.append(Variant(primitive.semantic_operation, width, encoding))
    if position != len(body):
        raise PackageError("trailing package bytes")
    return _validated(DecodedPackage("shared_primitive", target, tuple(contracts), tuple(variants)))


def _validated(package: DecodedPackage) -> DecodedPackage:
    if not package.contracts or not package.variants:
        raise PackageError("empty package")
    variants = {(item.semantic_operation, item.width) for item in package.variants}
    expected = {(operation, width) for operation in ARITHMETIC_OPS for width in WIDTHS}
    if variants != expected:
        raise PackageError("package does not cover exact arithmetic family")
    for contract in package.contracts:
        if contract.semantic_operation not in ARITHMETIC_OPS:
            raise PackageError("unknown semantic operation")
        if contract.input_arity != 2 or contract.output_arity != 1:
            raise PackageError("wrong semantic arity")
        if not contract.widths or any(width not in WIDTHS for width in contract.widths):
            raise PackageError("unsupported type width")
        if (contract.effects, contract.control, contract.memory, contract.optimization) != (
            PURE_EFFECTS, NO_CONTROL, NO_MEMORY, OPT_PURE_FOLD_CSE_REORDER
        ):
            raise PackageError("semantic behavior/restrictions mismatch")
    return package


def normalized_contracts(package: DecodedPackage) -> tuple[tuple[int, int, int, int, int, int, int], ...]:
    rows = []
    for variant in sorted(package.variants, key=lambda item: (item.semantic_operation, item.width)):
        matches = [
            contract for contract in package.contracts
            if contract.semantic_operation == variant.semantic_operation and variant.width in contract.widths
        ]
        if len(matches) != 1:
            raise PackageError("variant lacks one exact semantic contract")
        contract = matches[0]
        rows.append((
            variant.semantic_operation,
            variant.width,
            contract.input_arity,
            contract.output_arity,
            contract.effects,
            contract.control,
            contract.memory,
        ))
    return tuple(rows)


def package_identity(payload: bytes) -> str:
    return blake3(payload).hexdigest()


def model_description(package: DecodedPackage) -> bytes:
    """Compact deterministic AI-facing description; bytes are not token counts."""
    if package.form == "per_instruction":
        rows = []
        by_variant = {(item.semantic_operation, item.width): item for item in package.variants}
        for contract in sorted(package.contracts, key=lambda item: (item.semantic_operation, item.widths)):
            width = contract.widths[0]
            variant = by_variant[(contract.semantic_operation, width)]
            rows.append(
                f"i:{contract.semantic_operation}:{width}:2>{width},1>{width}:e{contract.effects}:c{contract.control}:m{contract.memory}:o{contract.optimization}:v{variant.encoding_variant}"
            )
    else:
        rows = [
            f"p:{contract.semantic_operation}:{','.join(map(str, contract.widths))}:2>n,1>n:e{contract.effects}:c{contract.control}:m{contract.memory}:o{contract.optimization}"
            for contract in sorted(package.contracts, key=lambda item: item.semantic_operation)
        ]
        index = {contract.semantic_operation: i for i, contract in enumerate(sorted(package.contracts, key=lambda item: item.semantic_operation))}
        rows.extend(
            f"v:{index[item.semantic_operation]}:{item.width}:{item.encoding_variant}"
            for item in sorted(package.variants, key=lambda item: (item.semantic_operation, item.width))
        )
    return (package.target + "|" + "|".join(rows)).encode("ascii")


OPAQUE_REQUIRED = ("inputs", "outputs", "effects", "control", "memory", "legality", "optimization")
CONTROL_REQUIRED = ("branch", "trap", "block", "synchronize", "terminate")
MEMORY_REQUIRED = ("access", "spaces", "ordering", "alias_visibility")
LEGALITY_REQUIRED = ("privilege", "execution_state")
OPT_REQUIRED = ("barrier",)


def validate_opaque_contract(contract: Mapping[str, object], *, accelerator: bool = False) -> str:
    for field in OPAQUE_REQUIRED:
        if field not in contract:
            raise PackageError(f"opaque contract missing {field}")
    control = contract["control"]
    memory = contract["memory"]
    legality = contract["legality"]
    optimization = contract["optimization"]
    if not isinstance(control, Mapping) or any(field not in control for field in CONTROL_REQUIRED):
        raise PackageError("opaque control behavior incomplete")
    if not isinstance(memory, Mapping) or any(field not in memory for field in MEMORY_REQUIRED):
        raise PackageError("opaque memory behavior incomplete")
    if not isinstance(legality, Mapping) or any(field not in legality for field in LEGALITY_REQUIRED):
        raise PackageError("opaque legality incomplete")
    if not isinstance(optimization, Mapping) or any(field not in optimization for field in OPT_REQUIRED):
        raise PackageError("opaque optimization restriction incomplete")
    if accelerator and bool(control["synchronize"]):
        for field in ("supported_scopes",):
            if field not in legality:
                raise PackageError(f"synchronizing accelerator contract missing {field}")
        for field in ("source_space", "destination_space", "visibility"):
            if field not in memory:
                raise PackageError(f"synchronizing accelerator contract missing {field}")
    return str(optimization["barrier"])


def opaque_fixtures() -> tuple[dict[str, object], dict[str, object]]:
    arithmetic = {
        "inputs": ["bits32", "bits32"],
        "outputs": ["bits32"],
        "effects": [],
        "control": {"branch": False, "trap": False, "block": False, "synchronize": False, "terminate": False},
        "memory": {"access": "none", "spaces": [], "ordering": "none", "alias_visibility": "none"},
        "legality": {"privilege": "none", "execution_state": "any"},
        "optimization": {"barrier": "none", "constant_fold": True, "cse": True},
    }
    accelerator = {
        "inputs": ["resource<buffer,device>", "effect<device>"],
        "outputs": ["resource<buffer,device>", "effect<device>"],
        "effects": ["device"],
        "control": {"branch": False, "trap": False, "block": True, "synchronize": True, "terminate": False},
        "memory": {
            "access": "read_write",
            "spaces": [1],
            "ordering": "barrier",
            "alias_visibility": "space1-visible",
            "source_space": 1,
            "destination_space": 1,
            "visibility": "device",
        },
        "legality": {"privilege": "none", "execution_state": "grid", "supported_scopes": ["device"]},
        "optimization": {"barrier": "device-space-1"},
    }
    return arithmetic, accelerator


def opaque_negative_matrix() -> dict[str, str]:
    arithmetic, accelerator = opaque_fixtures()
    result: dict[str, str] = {}
    for field in OPAQUE_REQUIRED:
        damaged = copy.deepcopy(arithmetic)
        del damaged[field]
        try:
            validate_opaque_contract(damaged)
        except PackageError as error:
            result[f"missing_{field}"] = str(error)
        else:
            raise AssertionError(f"missing {field} accepted")
    for container, fields in (("control", CONTROL_REQUIRED), ("memory", MEMORY_REQUIRED), ("legality", LEGALITY_REQUIRED), ("optimization", OPT_REQUIRED)):
        for field in fields:
            damaged = copy.deepcopy(arithmetic)
            del damaged[container][field]
            try:
                validate_opaque_contract(damaged)
            except PackageError as error:
                result[f"missing_{container}_{field}"] = str(error)
            else:
                raise AssertionError(f"missing {container}.{field} accepted")
    for container, fields in (("legality", ("supported_scopes",)), ("memory", ("source_space", "destination_space", "visibility"))):
        for field in fields:
            damaged = copy.deepcopy(accelerator)
            del damaged[container][field]
            try:
                validate_opaque_contract(damaged, accelerator=True)
            except PackageError as error:
                result[f"accelerator_missing_{container}_{field}"] = str(error)
            else:
                raise AssertionError(f"missing accelerator {container}.{field} accepted")
    return result


def fixture(width: int, target_object) -> tuple[StoreReader, object, object]:
    bits = bits_type(width)
    graph = graph_fragment((
        Block(
            (bits, bits, bits),
            (
                Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (bits,)),
                Node(Operation.SUB_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 2)), (bits,)),
            ),
            Terminator.return_((ValueRef.node_result(0, 1),)),
        ),
    ))
    entry = function(graph, (bits, bits, bits), (bits,))
    module = object_with_refs(Kind.MODULE, (bits, entry, target_object))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (bits, graph, entry, target_object, module, root)))
    verify_store(reader)
    return reader, entry, target_object


def _node_ranges(image, function_cid: bytes) -> tuple[int, ...]:
    ranges = sorted(
        (item for item in image.semantic_ranges if item.function_cid == function_cid and item.block_index is not None),
        key=lambda item: (item.block_index, item.node_index),
    )
    return tuple(item.end - item.start for item in ranges)


def lower_one(target_name: str, width: int, form: str):
    target_meta = TARGETS[target_name]
    target_object = target_meta["target"]()
    reader, entry, target_object = fixture(width, target_object)
    if form == "per_instruction":
        payload = encode_per_instruction(target_name)
        package = decode_per_instruction(payload)
    elif form == "shared_primitive":
        payload = encode_shared_primitives(target_name)
        package = decode_shared_primitives(payload)
    else:
        raise ValueError(form)
    contracts = normalized_contracts(package)
    required = {(operation, width) for operation in ARITHMETIC_OPS}
    if not required.issubset({(row[0], row[1]) for row in contracts}):
        raise PackageError("lowering family missing exact contract")
    image = target_meta["compile"](reader, entry.cid, target_object.cid)
    return reader, entry, image, payload, package


def _source_lines(function: Callable) -> int:
    return len(inspect.getsourcelines(function)[0])


def _timing_samples(sample_count: int = 20) -> dict[str, object]:
    raw: dict[str, dict[str, list[int]]] = {}
    forms = ("per_instruction", "shared_primitive")
    for target_name in TARGETS:
        raw[target_name] = {form: [] for form in forms}
        # Warm both candidate paths before recording.
        for form in forms:
            lower_one(target_name, 32, form)
        # Pair every width/sample and alternate arm order to avoid a systematic
        # warm-cache/order advantage for either measurement-only representation.
        for sample in range(sample_count):
            width = WIDTHS[sample & 1]
            order = forms if sample & 1 == 0 else tuple(reversed(forms))
            for form in order:
                start = time.perf_counter_ns()
                lower_one(target_name, width, form)
                raw[target_name][form].append(time.perf_counter_ns() - start)
    return {
        "schema": "xax.oi16.target-granularity.timing.v1",
        "host_observation_only": True,
        "sample_count_per_target_form": sample_count,
        "samples_ns": raw,
        "summary_ns": {
            target: {
                form: {
                    "median": int(statistics.median(samples)),
                    "min": min(samples),
                    "max": max(samples),
                }
                for form, samples in forms.items()
            }
            for target, forms in raw.items()
        },
    }


def _package_metrics(target_name: str) -> dict[str, object]:
    per_payload = encode_per_instruction(target_name)
    shared_payload = encode_shared_primitives(target_name)
    per = decode_per_instruction(per_payload)
    shared = decode_shared_primitives(shared_payload)
    if normalized_contracts(per) != normalized_contracts(shared):
        raise AssertionError("package forms do not normalize to equal semantic contracts")
    per_text = model_description(per)
    shared_text = model_description(shared)
    return {
        "per_instruction": {
            "package_cid": package_identity(per_payload),
            "package_bytes": len(per_payload),
            "objects": len(per.contracts),
            "model_description_bytes": len(per_text),
            "model_tokens": None,
        },
        "shared_primitive": {
            "package_cid": package_identity(shared_payload),
            "package_bytes": len(shared_payload),
            "objects": len(shared.contracts) + len(shared.variants),
            "semantic_primitives": len(shared.contracts),
            "encoding_variants": len(shared.variants),
            "model_description_bytes": len(shared_text),
            "model_tokens": None,
        },
        "equal_normalized_contracts": True,
        "add_new_width_bytes": {
            # Exact compact payload delta for one width/encoding: per instruction
            # must repeat two complete contracts, shared adds two 3-field variants.
            "per_instruction": sum(len(_u(value)) for operation in ARITHMETIC_OPS for value in (
                operation, 128, 2, 128, 128, 1, 128,
                PURE_EFFECTS, NO_CONTROL, NO_MEMORY, OPT_PURE_FOLD_CSE_REORDER,
                TARGETS[target_name]["variant_base"] + 0x40 + (operation - ARITHMETIC_OPS[0]) * 16,
            )),
            "shared_primitive": (
                sum(len(_u(128)) for _operation in ARITHMETIC_OPS)
                + sum(
                    len(_u(value)) for primitive_index, operation in enumerate(ARITHMETIC_OPS)
                    for value in (primitive_index, 128, TARGETS[target_name]["variant_base"] + 0x40 + primitive_index * 16)
                )
            ),
        },
    }


def deterministic_evidence() -> dict[str, object]:
    target_metrics = {target: _package_metrics(target) for target in TARGETS}
    lowerings: dict[str, object] = {}
    for target_name in TARGETS:
        target_rows = {}
        for width in WIDTHS:
            arms = {}
            digests = []
            node_sizes = []
            for form in ("per_instruction", "shared_primitive"):
                reader, entry, image, payload, package = lower_one(target_name, width, form)
                expected = execute(reader, entry.cid, (7, 3, 2))
                artifact = image.artifact_bytes
                row = {
                    "program_root": reader.root_cid.hex(),
                    "entry_function": entry.cid.hex(),
                    "package_cid": package_identity(payload),
                    "artifact_bytes": len(artifact),
                    "artifact_blake3": blake3(artifact).hexdigest(),
                    "node_code_bytes": list(_node_ranges(image, entry.cid)),
                    "semantic_reference_result": list(expected),
                }
                if target_name == "wasm32_core":
                    row["executed_result"] = list(run_wasm_isolated(image, (7, 3, 2)))
                    row["execution_matches_reference"] = tuple(row["executed_result"]) == expected
                else:
                    row["executed_result"] = None
                    row["execution_matches_reference"] = None
                arms[form] = row
                digests.append(row["artifact_blake3"])
                node_sizes.append(row["node_code_bytes"])
            target_rows[str(width)] = {
                "arms": arms,
                "identical_artifact_bytes": len(set(digests)) == 1,
                "identical_node_code_size": node_sizes[0] == node_sizes[1],
            }
        lowerings[target_name] = target_rows

    arithmetic, accelerator = opaque_fixtures()
    arithmetic_barrier = validate_opaque_contract(arithmetic)
    accelerator_barrier = validate_opaque_contract(accelerator, accelerator=True)
    negative = opaque_negative_matrix()

    return {
        "schema": "xax.oi16.target-granularity.evidence.v1",
        "date": "2026-10-02",
        "scope": "measurement-only target-description granularity over existing add/sub wrapping integer lowerings",
        "canonical_target_schema_changed": False,
        "targets": target_metrics,
        "aggregate": {
            "per_instruction_package_bytes": sum(item["per_instruction"]["package_bytes"] for item in target_metrics.values()),
            "shared_primitive_package_bytes": sum(item["shared_primitive"]["package_bytes"] for item in target_metrics.values()),
            "per_instruction_objects": sum(item["per_instruction"]["objects"] for item in target_metrics.values()),
            "shared_primitive_objects": sum(item["shared_primitive"]["objects"] for item in target_metrics.values()),
            "per_instruction_model_description_bytes": sum(item["per_instruction"]["model_description_bytes"] for item in target_metrics.values()),
            "shared_primitive_model_description_bytes": sum(item["shared_primitive"]["model_description_bytes"] for item in target_metrics.values()),
        },
        "lowering_equivalence": lowerings,
        "opaque_contract_minimum": {
            "required_top_level_fields": list(OPAQUE_REQUIRED),
            "required_control_fields": list(CONTROL_REQUIRED),
            "required_memory_fields": list(MEMORY_REQUIRED),
            "required_legality_fields": list(LEGALITY_REQUIRED),
            "required_optimization_fields": list(OPT_REQUIRED),
            "pure_arithmetic_barrier": arithmetic_barrier,
            "synchronizing_accelerator_barrier": accelerator_barrier,
            "accelerator_conditional_minimum": {
                "legality": ["supported_scopes"],
                "memory": ["source_space", "destination_space", "visibility"],
            },
            "negative_fixture_count": len(negative),
            "negative_rejections": negative,
            "missing_behavior_policy": "reject; never infer purity/memory/control",
        },
        "optimization": {
            "per_instruction_fold_cse_reorder_bits": OPT_PURE_FOLD_CSE_REORDER,
            "shared_primitive_fold_cse_reorder_bits": OPT_PURE_FOLD_CSE_REORDER,
            "opportunities_blocked_by_granularity_difference": 0,
            "complete_opaque_accelerator_barrier": "device-space-1",
            "global_unknown_barrier_used": False,
        },
        "implementation": {
            "per_instruction_encoder_lines": _source_lines(encode_per_instruction),
            "per_instruction_decoder_lines": _source_lines(decode_per_instruction),
            "shared_encoder_lines": _source_lines(encode_shared_primitives),
            "shared_decoder_lines": _source_lines(decode_shared_primitives),
            "opaque_validator_lines": _source_lines(validate_opaque_contract),
            "production_verifier_decoder_changed_functions": 0,
        },
        "token_measurement": {
            "available": False,
            "reason": "no tokenizer/model integration installed in execution environment",
            "bytes_are_not_tokens": True,
        },
        "timing": {
            "artifact": TIMING.name,
            "sample_count_per_target_form": 20,
            "semantic_fuel_or_guarantee": False,
        },
    }


def write_artifacts() -> tuple[dict[str, object], dict[str, object]]:
    evidence = deterministic_evidence()
    timing = _timing_samples()
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    TIMING.write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence, timing


def main() -> None:
    evidence, timing = write_artifacts()
    print(json.dumps({
        "evidence": str(EVIDENCE),
        "timing": str(TIMING),
        "targets": evidence["targets"],
        "timing_summary_ns": timing["summary_ns"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
