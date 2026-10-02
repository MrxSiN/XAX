"""OI-20 ABI/platform classification and capability granularity experiment.

All carriers in this benchmark are tooling-only.  They describe existing ABI
facts and platform authority; they do not participate in canonical XAX program
identity and do not change backend lowering.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from benchmarks.bench_android_arm64 import bionic_import_fixture
from xax_android import compile_android_shared, inspect_android_elf
from xax_compiler import (
    Block,
    FloatFormat,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    abi_homogeneous_float,
    abi_layout,
    aarch64_baremetal_general_target,
    android_arm64_shared_target,
    android_jni_invoke_operation,
    android_jni_native_operation,
    bits_type,
    decode_float_width,
    decode_foreign_function,
    decode_native_target,
    float_type,
    function,
    graph_fragment,
    object_with_refs,
    opaque_identity_type,
    tuple_type,
    uleb,
    verify_store,
    write_store,
    x86_64_windows_general_target,
)
from xax_x86_64 import compile_native
from xax_aarch64 import compile_aarch64

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "oi20_abi_platform_evidence.json"
RAW = HERE / "oi20_abi_platform_timing.json"
THIS_FILE = Path(__file__).resolve()
COMPILER = HERE.parent / "src" / "xax_compiler.py"
X86 = HERE.parent / "src" / "xax_x86_64.py"
AARCH64 = HERE.parent / "src" / "xax_aarch64.py"
ANDROID = HERE.parent / "src" / "xax_android.py"
JNI = HERE.parent / "src" / "xax_jni.py"

MAGIC = b"X20A"
VERSION = 1
MODE_POSITIONAL = 1       # Win64: one argument position chooses GPR/FPR bank.
MODE_SPLIT_BANKS = 2     # AAPCS64: independent GPR/FPR allocation cursors.

CAP_DYNAMIC_SYMBOL = 1
CAP_JNI_INVOKE_SLOT = 2
CAP_JNI_NATIVE_SLOT = 3
CAP_NAMES = {
    CAP_DYNAMIC_SYMBOL: "dynamic_symbol",
    CAP_JNI_INVOKE_SLOT: "jni_invoke_slot",
    CAP_JNI_NATIVE_SLOT: "jni_native_slot",
}


@dataclass(frozen=True)
class AbiCarrier:
    identity: bytes
    pointer_bytes: int
    stack_alignment: int
    shadow_space: int
    mode: int
    gpr_args: tuple[int, ...]
    fpr_args: tuple[int, ...]
    gpr_result: int
    fpr_result: int
    indirect_result_register: int
    scratch_registers: tuple[int, ...]
    direct_aggregate_sizes: tuple[int, ...]
    split_aggregate_max: int
    hfa_max_members: int
    hfa_member_sizes: tuple[int, ...]
    stack_slot_alignment: int


@dataclass(frozen=True)
class Location:
    kind: str
    index: int
    count: int = 1
    offset: int = 0
    indirect: bool = False


@dataclass(frozen=True)
class CapabilityRequirement:
    family: int
    parameters: tuple[bytes, ...]


@dataclass(frozen=True)
class ForeignContractSuggestion:
    declaration_cid: bytes
    abi_carrier_cid: bytes
    signature_digest: bytes
    input_locations: tuple[Location, ...]
    output_locations: tuple[Location, ...]
    authoritative: bool = False


def _bytes(value: bytes) -> bytes:
    return uleb(len(value)) + value


def encode_abi(carrier: AbiCarrier) -> bytes:
    out = bytearray(MAGIC + bytes((VERSION,)))
    out.extend(_bytes(carrier.identity))
    for value in (
        carrier.pointer_bytes, carrier.stack_alignment, carrier.shadow_space, carrier.mode,
        carrier.gpr_result, carrier.fpr_result, carrier.indirect_result_register,
        carrier.split_aggregate_max, carrier.hfa_max_members, carrier.stack_slot_alignment,
    ):
        out.extend(uleb(value))
    for values in (
        carrier.gpr_args, carrier.fpr_args, carrier.scratch_registers,
        carrier.direct_aggregate_sizes, carrier.hfa_member_sizes,
    ):
        out.extend(uleb(len(values)))
        for value in values:
            out.extend(uleb(value))
    digest = hashlib.sha256(out).digest()[:16]
    return bytes(out) + digest


def _read_uleb(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise ValueError("truncated ABI carrier")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if data[start:pos] != uleb(value):
                raise ValueError("noncanonical ABI carrier integer")
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("oversized ABI carrier integer")


def decode_abi(data: bytes) -> AbiCarrier:
    if len(data) < 5 + 16 or data[:4] != MAGIC or data[4] != VERSION:
        raise ValueError("wrong ABI carrier magic/version")
    body, digest = data[:-16], data[-16:]
    if hashlib.sha256(body).digest()[:16] != digest:
        raise ValueError("ABI carrier digest mismatch")
    pos = 5
    length, pos = _read_uleb(body, pos)
    if pos + length > len(body):
        raise ValueError("truncated ABI identity")
    identity = body[pos:pos + length]
    pos += length
    scalars = []
    for _ in range(10):
        value, pos = _read_uleb(body, pos)
        scalars.append(value)
    groups = []
    for _ in range(5):
        count, pos = _read_uleb(body, pos)
        values = []
        for _ in range(count):
            value, pos = _read_uleb(body, pos)
            values.append(value)
        groups.append(tuple(values))
    if pos != len(body):
        raise ValueError("trailing ABI carrier bytes")
    carrier = AbiCarrier(
        identity,
        scalars[0], scalars[1], scalars[2], scalars[3],
        groups[0], groups[1], scalars[4], scalars[5], scalars[6], groups[2],
        groups[3], scalars[7], scalars[8], groups[4], scalars[9],
    )
    if carrier.mode not in (MODE_POSITIONAL, MODE_SPLIT_BANKS):
        raise ValueError("unknown ABI classifier mode")
    if not carrier.identity or not carrier.gpr_args or not carrier.fpr_args:
        raise ValueError("incomplete ABI carrier")
    if tuple(sorted(set(carrier.direct_aggregate_sizes))) != carrier.direct_aggregate_sizes:
        raise ValueError("noncanonical direct aggregate sizes")
    return carrier


def carrier_cid(carrier: AbiCarrier) -> bytes:
    return hashlib.sha256(encode_abi(carrier)).digest()


def win64_carrier() -> AbiCarrier:
    target = decode_native_target(x86_64_windows_general_target())
    return AbiCarrier(
        b"windows-x64-v1", 8, target.stack_alignment, target.shadow_space, MODE_POSITIONAL,
        target.argument_registers, (0, 1, 2, 3), target.result_register or 0, 0, target.argument_registers[0],
        target.scratch_registers, (1, 2, 4, 8), 0, 0, (), 8,
    )


def aapcs64_carrier() -> AbiCarrier:
    target = decode_native_target(aarch64_baremetal_general_target())
    return AbiCarrier(
        b"aapcs64-v1", 8, target.stack_alignment, target.shadow_space, MODE_SPLIT_BANKS,
        target.argument_registers, tuple(range(8)), target.result_register or 0, 0, 8,
        target.scratch_registers, (), 16, 4, (4, 8), 8,
    )


def _android_carrier() -> AbiCarrier:
    base = aapcs64_carrier()
    return AbiCarrier(
        b"android-aapcs64-c-v1", base.pointer_bytes, base.stack_alignment, base.shadow_space, base.mode,
        base.gpr_args, base.fpr_args, base.gpr_result, base.fpr_result, base.indirect_result_register,
        base.scratch_registers, base.direct_aggregate_sizes, base.split_aggregate_max,
        base.hfa_max_members, base.hfa_member_sizes, base.stack_slot_alignment,
    )


def _type_form(obj: SemanticObject) -> int:
    if obj.kind != Kind.TYPE or not obj.body:
        raise ValueError("ABI value must be a type")
    return obj.body[0]


def _type_class(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject], carrier: AbiCarrier) -> tuple[str, int, int]:
    form = _type_form(obj)
    if form == 7:
        width = decode_float_width(obj)
        if width not in (32, 64):
            raise ValueError("abi.unclassifiable_type: unsupported float width")
        return ("float", 1, width // 8)
    if form in (1, 2):
        layout = abi_layout(obj, resolve, carrier.pointer_bytes)
        return ("integer", 1, layout.size)
    if form in (8, 9, 10):
        layout = abi_layout(obj, resolve, carrier.pointer_bytes)
        if layout.size in carrier.direct_aggregate_sizes:
            return ("integer", 1, layout.size)
        if carrier.hfa_max_members:
            hfa = abi_homogeneous_float(obj, resolve)
            if hfa is not None and hfa[0] in carrier.hfa_member_sizes and hfa[1] <= carrier.hfa_max_members:
                return ("hfa", hfa[1], hfa[0])
        if carrier.split_aggregate_max and layout.size <= carrier.split_aggregate_max:
            return ("gpr2", 2, layout.size)
        return ("ref", 1, layout.size)
    raise ValueError("abi.unclassifiable_type: unsupported type form")


def classify_signature(
    inputs: Sequence[SemanticObject], outputs: Sequence[SemanticObject],
    resolve: Callable[[bytes], SemanticObject], carrier: AbiCarrier,
) -> tuple[tuple[Location, ...], tuple[Location, ...], int]:
    if len(outputs) > 1:
        raise ValueError("abi.unclassifiable_type: multiple machine results")
    classes = [_type_class(obj, resolve, carrier) for obj in inputs]
    locations: list[Location] = []
    stack = carrier.shadow_space
    if carrier.mode == MODE_POSITIONAL:
        for position, (kind, _count, _member) in enumerate(classes):
            if position < len(carrier.gpr_args):
                bank = "fpr" if kind == "float" else "gpr"
                index = carrier.fpr_args[position] if bank == "fpr" else carrier.gpr_args[position]
                locations.append(Location(bank if kind != "ref" else "ref", index, indirect=kind == "ref"))
            else:
                locations.append(Location("stack", -1, offset=stack, indirect=kind == "ref"))
                stack += carrier.stack_slot_alignment
    else:
        ngpr = nfpr = 0
        for kind, count, member in classes:
            if kind in ("float", "hfa") and nfpr + count <= len(carrier.fpr_args):
                locations.append(Location("fpr" if kind == "float" else "hfa", carrier.fpr_args[nfpr], count))
                nfpr += count
                continue
            needed = 2 if kind == "gpr2" else 1
            if kind not in ("float", "hfa") and ngpr + needed <= len(carrier.gpr_args):
                locations.append(Location(kind, carrier.gpr_args[ngpr], needed, indirect=kind == "ref"))
                ngpr += needed
                continue
            stack = (stack + carrier.stack_slot_alignment - 1) // carrier.stack_slot_alignment * carrier.stack_slot_alignment
            locations.append(Location("stack", -1, count, stack, kind == "ref"))
            layout = abi_layout(inputs[len(locations) - 1], resolve, carrier.pointer_bytes)
            stack += carrier.pointer_bytes if kind == "ref" else max(carrier.stack_slot_alignment, layout.size)
    results: list[Location] = []
    if outputs:
        kind, count, _member = _type_class(outputs[0], resolve, carrier)
        if kind == "float":
            results.append(Location("fpr", carrier.fpr_result))
        elif kind == "hfa":
            results.append(Location("hfa", carrier.fpr_result, count))
        elif kind == "gpr2":
            results.append(Location("gpr2", carrier.gpr_result, count))
        elif kind == "ref":
            results.append(Location("ref", carrier.indirect_result_register, indirect=True))
        else:
            results.append(Location("gpr", carrier.gpr_result))
    stack = (stack + carrier.stack_alignment - 1) // carrier.stack_alignment * carrier.stack_alignment if stack else 0
    return tuple(locations), tuple(results), stack


def _reader(function_object: SemanticObject, objects: Sequence[SemanticObject], target: SemanticObject) -> StoreReader:
    module = object_with_refs(Kind.MODULE, (function_object, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (*objects, function_object, target, module, root)))


def _identity_fixture(target: SemanticObject, value_type: SemanticObject) -> tuple[StoreReader, SemanticObject]:
    graph = graph_fragment([Block((value_type,), (), Terminator.return_((ValueRef.parameter(0, 0),)))])
    fn = function(graph, (value_type,), (value_type,))
    return _reader(fn, (value_type, graph), target), fn


def _add_fixture(target: SemanticObject) -> tuple[StoreReader, SemanticObject]:
    b32 = bits_type(32)
    graph = graph_fragment([
        Block((b32, b32), (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
              Terminator.return_((ValueRef.node_result(0, 0),)))
    ])
    fn = function(graph, (b32, b32), (b32,))
    return _reader(fn, (b32, graph), target), fn


def _resolve(objects: Sequence[SemanticObject]) -> Callable[[bytes], SemanticObject]:
    table = {obj.cid: obj for obj in objects}
    return table.__getitem__


def type_corpus():
    b32, b64 = bits_type(32), bits_type(64)
    f32, f64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
    pair32 = tuple_type((b32, b32))
    pair64 = tuple_type((b64, b64))
    hfa4 = tuple_type((f32, f32, f32, f32))
    triple64 = tuple_type((b64, b64, b64))
    opaque = opaque_identity_type(b"oi20-unclassifiable")
    objects = (b32, b64, f32, f64, pair32, pair64, hfa4, triple64, opaque)
    return objects, {
        "b32": b32, "b64": b64, "f32": f32, "f64": f64,
        "pair32": pair32, "pair64": pair64, "hfa4": hfa4, "triple64": triple64,
        "opaque": opaque,
    }


def _location_json(location: Location) -> dict:
    return {
        "kind": location.kind, "index": location.index, "count": location.count,
        "offset": location.offset, "indirect": location.indirect,
    }


def _classification_matrix():
    objects, types = type_corpus()
    resolve = _resolve(objects)
    signatures = {
        "scalar_int": ((types["b32"], types["b64"]), (types["b32"],)),
        "mixed_scalar": ((types["b32"], types["f64"], types["b64"], types["f32"]), (types["f64"],)),
        "small_aggregate": ((types["pair32"],), (types["pair32"],)),
        "medium_aggregate": ((types["pair64"],), (types["pair64"],)),
        "hfa4": ((types["hfa4"],), (types["hfa4"],)),
        "large_aggregate": ((types["triple64"],), (types["triple64"],)),
        "stack_pressure": ((types["b64"],) * 10, (types["b64"],)),
    }
    out = {}
    for name, carrier in (("win64", win64_carrier()), ("aapcs64", aapcs64_carrier()), ("android_aapcs64", _android_carrier())):
        records = {}
        for sig_name, (inputs, outputs) in signatures.items():
            ins, outs, stack = classify_signature(inputs, outputs, resolve, carrier)
            records[sig_name] = {
                "inputs": [_location_json(item) for item in ins],
                "outputs": [_location_json(item) for item in outs],
                "stack_bytes": stack,
            }
        out[name] = records
    return out


def _compile_equivalence():
    rows = []
    x86_target = x86_64_windows_general_target()
    x86_reader, x86_fn = _add_fixture(x86_target)
    x86_baseline = compile_native(x86_reader, x86_fn.cid, x86_target.cid).artifact_bytes
    # Candidate representation only validates/classifies; lowering remains the
    # unchanged backend, so exact bytes must be preserved.
    _ = win64_carrier()
    x86_candidate = compile_native(x86_reader, x86_fn.cid, x86_target.cid).artifact_bytes
    rows.append({"boundary": "windows_x86_64", "bytes": len(x86_baseline), "sha256": hashlib.sha256(x86_baseline).hexdigest(), "identical": x86_baseline == x86_candidate})

    arm_target = aarch64_baremetal_general_target()
    arm_reader, arm_fn = _add_fixture(arm_target)
    arm_baseline = compile_aarch64(arm_reader, arm_fn.cid, arm_target.cid).artifact_bytes
    _ = aapcs64_carrier()
    arm_candidate = compile_aarch64(arm_reader, arm_fn.cid, arm_target.cid).artifact_bytes
    rows.append({"boundary": "aapcs64_baremetal", "bytes": len(arm_baseline), "sha256": hashlib.sha256(arm_baseline).hexdigest(), "identical": arm_baseline == arm_candidate})

    reader, target, fn, exports = bionic_import_fixture()
    android_baseline = compile_android_shared(reader, exports, target_object=target).data
    view = inspect_android_elf(android_baseline)
    _ = _android_carrier()
    android_candidate = compile_android_shared(reader, exports, target_object=target).data
    rows.append({
        "boundary": "android_aapcs64_bionic", "bytes": len(android_baseline),
        "sha256": hashlib.sha256(android_baseline).hexdigest(), "identical": android_baseline == android_candidate,
        "imports": [item.decode("ascii") for item in view.imports], "needed": [item.decode("ascii") for item in view.needed],
    })
    return rows


def _signature_digest(declaration) -> bytes:
    h = hashlib.sha256()
    h.update(declaration.abi)
    for group in (declaration.inputs, declaration.outputs):
        h.update(uleb(len(group)))
        for cid in group:
            h.update(cid)
    return h.digest()


def suggest_foreign_contract(declaration: SemanticObject, carrier: AbiCarrier, resolve: Callable[[bytes], SemanticObject]) -> ForeignContractSuggestion:
    desc = decode_foreign_function(declaration)
    if desc.abi not in (b"android-aapcs64-c", b"aapcs64") or carrier.mode != MODE_SPLIT_BANKS:
        raise ValueError("foreign ABI metadata does not match classifier")
    # Effect/resource proof types are intentionally excluded from machine ABI placement.
    def machine(cids):
        values = []
        for cid in cids:
            obj = resolve(cid)
            try:
                _type_class(obj, resolve, carrier)
            except ValueError:
                continue
            values.append(obj)
        return tuple(values)
    ins, outs, _ = classify_signature(machine(desc.inputs), machine(desc.outputs), resolve, carrier)
    return ForeignContractSuggestion(declaration.cid, carrier_cid(carrier), _signature_digest(desc), ins, outs, False)


def _materialize(suggestion: ForeignContractSuggestion, declaration: SemanticObject, carrier: AbiCarrier, resolve: Callable[[bytes], SemanticObject]) -> ForeignContractSuggestion:
    expected = suggest_foreign_contract(declaration, carrier, resolve)
    if suggestion.authoritative or suggestion != expected:
        raise ValueError("foreign.contract_inference_mismatch")
    return ForeignContractSuggestion(
        suggestion.declaration_cid, suggestion.abi_carrier_cid, suggestion.signature_digest,
        suggestion.input_locations, suggestion.output_locations, True,
    )


def capability_satisfied(available: Sequence[CapabilityRequirement], requirement: CapabilityRequirement, *, parameterized: bool) -> bool:
    if requirement.family not in CAP_NAMES:
        return False
    if parameterized:
        return requirement in tuple(available)
    return any(item.family == requirement.family for item in available)


def encode_capability(requirement: CapabilityRequirement, *, parameterized: bool) -> bytes:
    if requirement.family not in CAP_NAMES:
        raise ValueError("platform.missing_capability")
    out = bytearray(b"X20C" + bytes((1, requirement.family)))
    if parameterized:
        out.extend(uleb(len(requirement.parameters)))
        for value in requirement.parameters:
            out.extend(_bytes(value))
    else:
        out.extend(b"\x00")
    return bytes(out)


def _capability_experiment():
    # Existing real cases: bionic getpid import, JNI invocation GetEnv slot 6,
    # and JNI native-interface FindClass slot 6.  Coarse family authority grants
    # every operation currently present in that family; parameterization grants
    # exactly one requested member.
    cases = (
        ("bionic_getpid", CapabilityRequirement(CAP_DYNAMIC_SYMBOL, (b"libc.so", b"getpid")), 14),  # POSIX API fixture symbols
        ("jni_getenv", CapabilityRequirement(CAP_JNI_INVOKE_SLOT, (b"6",)), 5),
        ("jni_findclass", CapabilityRequirement(CAP_JNI_NATIVE_SLOT, (b"6",)), 229),
    )
    rows = []
    for name, req, family_size in cases:
        coarse = encode_capability(req, parameterized=False)
        narrow = encode_capability(req, parameterized=True)
        if req.family == CAP_DYNAMIC_SYMBOL:
            unrelated = CapabilityRequirement(req.family, (b"libc.so", b"write"))
        else:
            slot = int(req.parameters[0]) + 1
            unrelated = CapabilityRequirement(req.family, (str(slot).encode("ascii"),))
        rows.append({
            "case": name, "family": CAP_NAMES[req.family], "family_members": family_size,
            "coarse_bytes": len(coarse), "parameterized_bytes": len(narrow),
            "coarse_authority_overgrant_members": family_size - 1,
            "parameterized_authority_overgrant_members": 0,
            "requested_parameters": [value.decode("ascii") for value in req.parameters],
            "requested_satisfied_coarse": capability_satisfied((req,), req, parameterized=False),
            "requested_satisfied_parameterized": capability_satisfied((req,), req, parameterized=True),
            "unrelated_same_family_satisfied_coarse": capability_satisfied((req,), unrelated, parameterized=False),
            "unrelated_same_family_satisfied_parameterized": capability_satisfied((req,), unrelated, parameterized=True),
        })
    # Deterministic unsupported requirement: invocation slot 7 is legal, 8 is not.
    unsupported = {"family": "jni_invoke_slot", "parameter": 8, "diagnostic": "platform.unsupported_operation"}
    try:
        android_jni_invoke_operation(8)
    except ValueError:
        unsupported["rejected"] = True
    else:
        unsupported["rejected"] = False
    return rows, unsupported


def _foreign_inference_evidence():
    reader, target, _fn, _exports = bionic_import_fixture()
    verify_store(reader)
    objects = tuple(reader.objects())
    foreign = next(obj for obj in objects if obj.kind == Kind.TARGET and b"foreign-function" in obj.body)
    resolve = _resolve(objects)
    carrier = _android_carrier()
    suggestion = suggest_foreign_contract(foreign, carrier, resolve)
    materialized = _materialize(suggestion, foreign, carrier, resolve)
    wrong = ForeignContractSuggestion(
        suggestion.declaration_cid, suggestion.abi_carrier_cid, b"\x00" * 32,
        suggestion.input_locations, suggestion.output_locations, False,
    )
    mismatch_rejected = False
    try:
        _materialize(wrong, foreign, carrier, resolve)
    except ValueError:
        mismatch_rejected = True
    return {
        "declaration_cid": foreign.cid.hex(), "carrier_cid": carrier_cid(carrier).hex(),
        "suggestion_authoritative": suggestion.authoritative,
        "materialized_authoritative": materialized.authoritative,
        "signature_digest": suggestion.signature_digest.hex(),
        "input_locations": [_location_json(item) for item in suggestion.input_locations],
        "output_locations": [_location_json(item) for item in suggestion.output_locations],
        "mismatch_rejected": mismatch_rejected,
    }


def _package_metrics():
    carriers = {"win64": win64_carrier(), "aapcs64": aapcs64_carrier(), "android_aapcs64": _android_carrier()}
    encoded = {name: encode_abi(value) for name, value in carriers.items()}
    # Android reuses all classification fields from AAPCS64 except identity.
    a, d = carriers["aapcs64"], carriers["android_aapcs64"]
    shared_fields = sum(
        getattr(a, field) == getattr(d, field)
        for field in a.__dataclass_fields__
        if field != "identity"
    )
    total_fields = len(a.__dataclass_fields__) - 1
    return {
        "carriers": {
            name: {"bytes": len(data), "cid": carrier_cid(carriers[name]).hex()}
            for name, data in encoded.items()
        },
        "total_bytes": sum(map(len, encoded.values())),
        "aapcs64_android_reused_classification_fields": shared_fields,
        "aapcs64_android_classification_fields": total_fields,
        "candidate_objects": len(encoded),
    }


def _implementation_metrics():
    text = THIS_FILE.read_text()
    classifier_start = text.index("def _type_class")
    classifier_end = text.index("def _reader", classifier_start)
    classifier_lines = sum(1 for line in text[classifier_start:classifier_end].splitlines() if line.strip() and not line.lstrip().startswith("#"))
    codec_start = text.index("def encode_abi")
    codec_end = text.index("def carrier_cid", codec_start)
    codec_lines = sum(1 for line in text[codec_start:codec_end].splitlines() if line.strip() and not line.lstrip().startswith("#"))
    # Existing hardcoded classification helpers being normalized by the candidate.
    existing = 0
    for path, starts in (
        (X86, ("def _win64_by_reference", "def _abi_kind")),
        (AARCH64, ("def _abi_class", "def _assign_arguments", "def _abi_argument_plan")),
    ):
        source = path.read_text()
        lines = source.splitlines()
        for start in starts:
            index = next(i for i, line in enumerate(lines) if line.startswith(start))
            end = index + 1
            while end < len(lines) and not (lines[end].startswith("def ") and end > index):
                end += 1
            existing += sum(1 for line in lines[index:end] if line.strip() and not line.lstrip().startswith("#"))
    return {
        "benchmark_codec_lines": codec_lines,
        "benchmark_classifier_lines": classifier_lines,
        "existing_abi_classification_helper_lines": existing,
        "production_lines_removed": 0,
        "production_lines_added": 0,
    }


def _diagnostics():
    objects, types = type_corpus()
    resolve = _resolve(objects)
    unclassifiable = False
    diagnostic = ""
    try:
        classify_signature((types["opaque"],), (), resolve, win64_carrier())
    except ValueError as error:
        unclassifiable, diagnostic = True, str(error)
    return {"unclassifiable_signature_rejected": unclassifiable, "diagnostic": diagnostic}



def _inventory():
    x86 = decode_native_target(x86_64_windows_general_target())
    arm = decode_native_target(aarch64_baremetal_general_target())
    android = decode_native_target(android_arm64_shared_target())
    _reader0, _target0, _fn0, exports = bionic_import_fixture()
    shared = compile_android_shared(_reader0, exports, target_object=_target0)
    view = inspect_android_elf(shared.data)
    return {
        "windows_x86_64": {
            "argument_registers": list(x86.argument_registers), "result_register": x86.result_register,
            "scratch_registers": list(x86.scratch_registers), "stack_alignment": x86.stack_alignment,
            "shadow_space": x86.shadow_space, "aggregate_rule": "1/2/4/8-byte aggregate direct; other aggregate by reference",
            "imports_relocations": "raw-load-image fixture has no dynamic foreign-import model",
            "full_call_clobber_set_present": False,
        },
        "aapcs64_baremetal": {
            "argument_registers": list(arm.argument_registers), "result_register": arm.result_register,
            "scratch_registers": list(arm.scratch_registers), "stack_alignment": arm.stack_alignment,
            "shadow_space": arm.shadow_space, "aggregate_rule": "HFA<=4 V regs; <=8 one X; <=16 X pair; >16 by reference",
            "imports_relocations": "bare-metal image fixture has no dynamic foreign-import model",
            "full_call_clobber_set_present": False,
        },
        "android_aapcs64": {
            "argument_registers": list(android.argument_registers), "result_register": android.result_register,
            "scratch_registers": list(android.scratch_registers), "stack_alignment": android.stack_alignment,
            "shadow_space": android.shadow_space, "classification_reuses_aapcs64": True,
            "platform_target_operations": len(android.target_operations),
            "bionic_fixture_imports": [x.decode("ascii") for x in view.imports],
            "bionic_fixture_needed": [x.decode("ascii") for x in view.needed],
            "bionic_fixture_relocations": view.relocation_count,
            "full_call_clobber_set_present": False,
        },
    }


def _backend_conformance():
    from xax_aarch64 import _abi_argument_plan as arm_plan
    from xax_x86_64 import _win64_by_reference, _abi_kind
    objects, types = type_corpus()
    resolve = _resolve(objects)
    aapcs = aapcs64_carrier()
    win = win64_carrier()
    arm_types = (types["b32"], types["f64"], types["pair64"], types["hfa4"], types["triple64"])
    candidate_locations, _out, candidate_stack = classify_signature(arm_types, (), resolve, aapcs)
    backend_plan, backend_stack = arm_plan(tuple(obj.cid for obj in arm_types), resolve)
    normalized_backend = []
    for (kind, index, count, _member) in backend_plan:
        normalized_backend.append({"kind": kind, "index": index, "count": count})
    normalized_candidate = [{"kind": loc.kind, "index": loc.index, "count": loc.count} for loc in candidate_locations]
    # Candidate names integer classes more explicitly, but physical location/count must match.
    aliases = {"integer": "gpr", "gpr": "gpr", "gpr2": "gpr2", "ref": "ref", "fpr": "fpr", "hfa": "hfa", "stack": "stack"}
    physical_match = len(normalized_backend) == len(normalized_candidate) and all(
        aliases.get(c["kind"], c["kind"]) == b["kind"] and c["index"] == b["index"] and c["count"] == b["count"]
        for c, b in zip(normalized_candidate, normalized_backend)
    ) and candidate_stack == backend_stack
    win_rows = []
    for name in ("b32", "f64", "pair32", "pair64", "hfa4", "triple64"):
        obj = types[name]
        kind, _, _ = _type_class(obj, resolve, win)
        win_rows.append({
            "type": name, "candidate_by_reference": kind == "ref",
            "backend_by_reference": _win64_by_reference(resolve, obj.cid),
            "backend_kind": _abi_kind(resolve, obj.cid),
        })
    return {
        "aapcs64_physical_plan_match": physical_match, "aapcs64_candidate_stack_bytes": candidate_stack,
        "aapcs64_backend_stack_bytes": backend_stack, "win64_rows": win_rows,
        "win64_by_reference_match": all(row["candidate_by_reference"] == row["backend_by_reference"] for row in win_rows),
    }


def _ai_payload():
    # Compact machine query: version, verb=classify, carrier-CID, input count + local type handles, output count.
    query = bytes((1, 1)) + carrier_cid(aapcs64_carrier()) + uleb(4) + b"\x00\x01\x02\x03" + uleb(1) + b"\x04"
    coarse = encode_capability(CapabilityRequirement(CAP_JNI_NATIVE_SLOT, (b"6",)), parameterized=False)
    narrow = encode_capability(CapabilityRequirement(CAP_JNI_NATIVE_SLOT, (b"6",)), parameterized=True)
    mutation = bytes((1, 2, CAP_JNI_NATIVE_SLOT)) + _bytes(b"6")
    return {
        "classification_query_bytes": len(query), "parameterized_capability_mutation_bytes": len(mutation),
        "coarse_capability_bytes": len(coarse), "parameterized_capability_bytes": len(narrow),
        "tokenizer_model_tokens": None,
    }

def collect_deterministic_evidence() -> dict:
    cap_rows, unsupported = _capability_experiment()
    return {
        "version": 1,
        "candidate": "data-driven ABI classifier carrier + parameterized platform capability family",
        "canonical_semantics_changed": False,
        "inventory": _inventory(),
        "classification": _classification_matrix(),
        "backend_conformance": _backend_conformance(),
        "package": _package_metrics(),
        "compile_equivalence": _compile_equivalence(),
        "capabilities": {"cases": cap_rows, "unsupported": unsupported},
        "foreign_inference": _foreign_inference_evidence(),
        "diagnostics": _diagnostics(),
        "implementation": _implementation_metrics(),
        "ai_payload": _ai_payload(),
        "model_tokens": None,
    }


def collect_raw(samples: int = 21) -> dict:
    objects, types = type_corpus()
    resolve = _resolve(objects)
    workload = ((types["b32"], types["f64"], types["pair64"], types["hfa4"], types["triple64"]), (types["b64"],))
    rows = {}
    for name, carrier in (("win64", win64_carrier()), ("aapcs64", aapcs64_carrier()), ("android_aapcs64", _android_carrier())):
        values = []
        peaks = []
        # warmup
        for _ in range(100):
            classify_signature(*workload, resolve, carrier)
        for _ in range(samples):
            start = time.perf_counter_ns()
            for _ in range(1000):
                classify_signature(*workload, resolve, carrier)
            elapsed = time.perf_counter_ns() - start
            values.append(elapsed / 1000.0)
            tracemalloc.start()
            classify_signature(*workload, resolve, carrier)
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peaks.append(peak)
        rows[name] = {"ns_per_classification": values, "peak_bytes": peaks}
    return {
        "host": {"platform": platform.platform(), "python": sys.version.split()[0], "machine": platform.machine()},
        "samples": samples,
        "rows": rows,
    }


def evidence_from_raw(deterministic: dict, raw: dict) -> dict:
    evidence = json.loads(json.dumps(deterministic))
    timing = {}
    for name, row in raw["rows"].items():
        values = row["ns_per_classification"]
        peaks = row["peak_bytes"]
        timing[name] = {
            "median_us": statistics.median(values) / 1000.0,
            "p10_us": sorted(values)[max(0, int(len(values) * 0.1) - 1)] / 1000.0,
            "p90_us": sorted(values)[min(len(values) - 1, int(len(values) * 0.9))] / 1000.0,
            "median_peak_bytes": int(statistics.median(peaks)),
            "semantic": False,
        }
    evidence["host_observed_classifier_cost"] = timing
    evidence["raw_sha256"] = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return evidence


def write_evidence(measure: bool = False) -> dict:
    deterministic = collect_deterministic_evidence()
    if measure or not RAW.exists():
        raw = collect_raw()
        RAW.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    else:
        raw = json.loads(RAW.read_text())
    evidence = evidence_from_raw(deterministic, raw)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", action="store_true")
    args = parser.parse_args()
    evidence = write_evidence(args.measure)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
