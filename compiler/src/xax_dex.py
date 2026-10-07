"""Minimal deterministic direct DEX 039 emission for synthesized Android bridge classes.

This module emits DEX bytes directly.  It does not generate Java/Kotlin source and it
has no D8/R8 dependency.  The current surface is intentionally narrow: one concrete
class, a generated constructor that invokes the superclass constructor, and zero or
more native virtual methods.  That is enough to synthesize the first ART-visible XAX
bridge without pretending the general DEX backend is complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import struct
import zlib
from typing import Iterable, Sequence


DEX039_MAGIC = b"dex\n039\x00"
DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_CONSTANT = 0x12345678
NO_INDEX = 0xFFFFFFFF

# access_flags
ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SUPER = 0x0020
ACC_NATIVE = 0x0100
ACC_ABSTRACT = 0x0400
ACC_SYNTHETIC = 0x1000
ACC_CONSTRUCTOR = 0x10000

# map_item type codes
TYPE_HEADER_ITEM = 0x0000
TYPE_STRING_ID_ITEM = 0x0001
TYPE_TYPE_ID_ITEM = 0x0002
TYPE_PROTO_ID_ITEM = 0x0003
TYPE_FIELD_ID_ITEM = 0x0004
TYPE_METHOD_ID_ITEM = 0x0005
TYPE_CLASS_DEF_ITEM = 0x0006
TYPE_MAP_LIST = 0x1000
TYPE_TYPE_LIST = 0x1001
TYPE_CLASS_DATA_ITEM = 0x2000
TYPE_CODE_ITEM = 0x2001
TYPE_STRING_DATA_ITEM = 0x2002


@dataclass(frozen=True, order=True)
class DexProto:
    return_type: str = "V"
    parameters: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_type_descriptor(self.return_type, allow_void=True)
        for item in self.parameters:
            _validate_type_descriptor(item, allow_void=False)


@dataclass(frozen=True, order=True)
class DexNativeMethod:
    name: str
    proto: DexProto = field(default_factory=DexProto)
    access_flags: int = ACC_PUBLIC | ACC_NATIVE

    def __post_init__(self) -> None:
        _validate_member_name(self.name)
        if not (self.access_flags & ACC_NATIVE):
            raise ValueError("bridge native method must carry ACC_NATIVE")
        if self.access_flags & ACC_STATIC:
            raise ValueError("bridge native method must currently be an instance method")


@dataclass(frozen=True, order=True)
class DexForwardingOverride:
    """Managed virtual method that forwards to one private native callback.

    ``call_super`` is true for lifecycle overrides such as ``Activity.onCreate``
    and false for interface callbacks such as ``View.OnClickListener.onClick``.
    Both forms cross into native XAX exactly once.
    """

    name: str
    proto: DexProto
    native_target: str
    access_flags: int = ACC_PROTECTED
    call_super: bool = True

    def __post_init__(self) -> None:
        _validate_member_name(self.name)
        _validate_member_name(self.native_target)
        if self.access_flags & (ACC_STATIC | ACC_NATIVE | ACC_PRIVATE):
            raise ValueError("forwarding override must be a non-static managed virtual method")
        if self.call_super and self.proto.return_type != "V":
            raise ValueError("a super-calling forwarding override must be void")

    @property
    def compact(self) -> bool:
        """The original 35c form: void, one-register parameters, at most four registers (``register_word``
        packs C..F only; a fifth register would belong in the first unit's G field)."""
        return self.proto.return_type == "V" and not any(item in {"J", "D"} for item in self.proto.parameters) and len(self.proto.parameters) <= 3


@dataclass(frozen=True, order=True)
class DexNullReturnOverride:
    """Managed virtual method that returns a null reference directly.

    This is a bounded DEX lowering primitive used when the exact platform
    contract permits a null object result. It allocates nothing and performs
    no native transition.
    """

    name: str
    proto: DexProto
    access_flags: int = ACC_PUBLIC

    def __post_init__(self) -> None:
        _validate_member_name(self.name)
        if self.access_flags & (ACC_STATIC | ACC_NATIVE | ACC_PRIVATE):
            raise ValueError("null-return override must be a non-static managed virtual method")
        if not self.proto.return_type.startswith(("L", "[")):
            raise ValueError("null-return override requires reference result")
        if any(item in {"J", "D"} for item in self.proto.parameters):
            raise ValueError("null-return override currently supports only one-register parameters")


@dataclass(frozen=True, order=True)
class DexActivityUiSpec:
    """Bounded managed Activity UI setup emitted directly as DEX.

    Text can be either one inline constant or one exact Android string resource ID.
    The representation choice is explicit lowering data; no runtime lookup helper is
    introduced by the compiler.
    """

    listener_class_descriptor: str
    button_text: str | None = None
    button_text_resource_id: int | None = None
    button_text_method_name: str | None = None
    button_text_method_argument: str | None = None

    def __post_init__(self) -> None:
        _validate_class_descriptor(self.listener_class_descriptor)
        choices = sum(
            item is not None
            for item in (self.button_text, self.button_text_resource_id, self.button_text_method_name)
        )
        if choices != 1:
            raise ValueError("Activity button text requires exactly one inline string, resource ID, or managed method")
        if self.button_text is not None and (not self.button_text or "\x00" in self.button_text):
            raise ValueError("Activity button text must be nonempty and NUL-free")
        if self.button_text_resource_id is not None and not 0 < self.button_text_resource_id <= 0xFFFFFFFF:
            raise ValueError("Activity button text resource ID must be a nonzero uint32")
        if self.button_text_method_name is not None:
            _validate_member_name(self.button_text_method_name)
        if self.button_text_method_argument is not None:
            if self.button_text_method_name is None:
                raise ValueError("Activity managed method argument requires managed method source")
            if not self.button_text_method_argument or "\x00" in self.button_text_method_argument:
                raise ValueError("Activity managed method argument must be nonempty and NUL-free")


@dataclass(frozen=True, order=True)
class DexConstantStringMethod:
    """Bounded managed instance method returning one constant Java String."""

    name: str
    value: str
    access_flags: int = ACC_PUBLIC

    def __post_init__(self) -> None:
        _validate_member_name(self.name)
        if not self.value or "\x00" in self.value:
            raise ValueError("constant string method value must be nonempty and NUL-free")
        if self.access_flags & (ACC_STATIC | ACC_NATIVE | ACC_PRIVATE):
            raise ValueError("constant string method must be a non-static managed virtual method")

    @property
    def proto(self) -> DexProto:
        return DexProto("Ljava/lang/String;", ())


@dataclass(frozen=True, order=True)
class DexEchoStringMethod:
    """Bounded public instance method ``String f(String value) { return value; }``."""

    name: str
    access_flags: int = ACC_PUBLIC

    def __post_init__(self) -> None:
        _validate_member_name(self.name)
        if self.access_flags & (ACC_STATIC | ACC_NATIVE | ACC_PRIVATE):
            raise ValueError("echo string method must be a non-static managed virtual method")

    @property
    def proto(self) -> DexProto:
        return DexProto("Ljava/lang/String;", ("Ljava/lang/String;",))


@dataclass(frozen=True, order=True)
class DexClickTextSpec:
    """Bounded managed click-state mutation for a generated listener adapter."""

    text: str | None = None
    text_resource_id: int | None = None

    def __post_init__(self) -> None:
        if (self.text is None) == (self.text_resource_id is None):
            raise ValueError("click text requires exactly one inline string or resource ID")
        if self.text is not None and (not self.text or "\x00" in self.text):
            raise ValueError("click text must be nonempty and NUL-free")
        if self.text_resource_id is not None and not 0 < self.text_resource_id <= 0xFFFFFFFF:
            raise ValueError("click text resource ID must be a nonzero uint32")


@dataclass(frozen=True, order=True)
class DexLibxposedHookInterceptSpec:
    """Bounded modern-libxposed interceptor-chain method.

    The current profile deliberately proves only the stable hot-path ABI needed
    for a pass-through hook: inspect one argument with ``Chain.getArg(int)``,
    invoke ``Chain.proceed()`` exactly once, and return that result.  Hook
    installation, argument replacement, result replacement, and exception-mode
    policy remain separate semantic/lowering work rather than being hidden in
    this DEX primitive.
    """

    inspected_argument_index: int | None = 0
    replacement_string: str | None = None
    argument_replacement_string: str | None = None

    def __post_init__(self) -> None:
        if self.inspected_argument_index is not None and not 0 <= self.inspected_argument_index <= 7:
            raise ValueError("bounded libxposed hook interceptor supports argument indices 0..7 or no inspection")
        if self.replacement_string is not None:
            if self.inspected_argument_index is not None and self.argument_replacement_string is None:
                raise ValueError("bounded result replacement currently requires a zero-argument/pure-proceed hook adapter")
            if not self.replacement_string or "\x00" in self.replacement_string:
                raise ValueError("libxposed replacement String must be nonempty and NUL-free")
        if self.argument_replacement_string is not None:
            if self.inspected_argument_index != 0:
                raise ValueError("bounded argument replacement currently requires inspected argument index 0")
            if not self.argument_replacement_string or "\x00" in self.argument_replacement_string:
                raise ValueError("libxposed replacement argument String must be nonempty and NUL-free")
            if self.replacement_string is not None and (not self.replacement_string or "\x00" in self.replacement_string):
                raise ValueError("libxposed replacement result String must be nonempty and NUL-free")


@dataclass(frozen=True, order=True)
class DexLibxposedHookInstallSpec:
    """One explicit API-102 hook installation performed during package-ready.

    The bounded profile resolves one supported method through the package
    ClassLoader, selects PROTECTIVE exception policy, instantiates one generated
    Hooker, and installs it.  ``process`` lifetime discards the returned
    HookHandle; ``retained-manual-unhook`` stores it in the generated module and
    exposes an idempotent ``xaxUnhook()`` method.  No lookup appears in the
    interceptor hot path.
    """

    target_class_binary_name: str
    target_method_name: str
    hooker_class_descriptor: str
    parameter_type_binary_names: tuple[str, ...] = ()
    exception_mode: str = "PROTECTIVE"
    failure_policy: str = "propagate"
    lifetime_policy: str = "process"
    deoptimize_before_hook: bool = False
    hook_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.target_class_binary_name
            or "\x00" in self.target_class_binary_name
            or "/" in self.target_class_binary_name
            or self.target_class_binary_name.startswith(".")
            or self.target_class_binary_name.endswith(".")
            or ".." in self.target_class_binary_name
        ):
            raise ValueError("invalid libxposed hook target binary class name")
        _validate_member_name(self.target_method_name)
        _validate_class_descriptor(self.hooker_class_descriptor)
        if self.parameter_type_binary_names not in ((), ("java.lang.String",)):
            raise ValueError("bounded libxposed hook installation supports zero args or one java.lang.String parameter")
        if self.exception_mode != "PROTECTIVE":
            raise ValueError("bounded libxposed hook installation requires PROTECTIVE exception mode")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed hook installation requires propagate failure policy")
        if self.lifetime_policy not in ("process", "retained-manual-unhook"):
            raise ValueError("bounded libxposed hook installation requires process or retained-manual-unhook lifetime")
        if not isinstance(self.deoptimize_before_hook, bool):
            raise ValueError("libxposed deoptimize-before-hook flag must be boolean")
        if self.hook_id is not None and (not self.hook_id or "\x00" in self.hook_id or "\n" in self.hook_id or "\r" in self.hook_id):
            raise ValueError("libxposed hook ID must be nonempty single-line text")


@dataclass(frozen=True, order=True)
class DexLibxposedModuleServicesSpec:
    """Explicit generated wrappers for selected libxposed module services.

    These wrappers contain no caching or hidden exception handling. Remote
    operations therefore preserve the framework's UnsupportedOperationException /
    FileNotFoundException behavior under the current propagate policy.
    """

    services: tuple[str, ...]
    failure_policy: str = "propagate"

    def __post_init__(self) -> None:
        allowed = (
            "framework-name",
            "framework-version",
            "remote-preferences",
            "list-remote-files",
            "open-remote-file",
        )
        ordered = tuple(item for item in allowed if item in self.services)
        if not ordered or len(self.services) != len(set(self.services)) or any(item not in allowed for item in self.services):
            raise ValueError("invalid libxposed module-service selection")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed module services require explicit propagate failure policy")
        object.__setattr__(self, "services", ordered)


@dataclass(frozen=True, order=True)
class DexLibxposedRemotePreferencesSpec:
    """Capability-gated remote preferences acquisition plus typed read helpers."""

    reads: tuple[str, ...]
    capability_policy: str = "nullable-on-unsupported"
    failure_policy: str = "propagate"

    def __post_init__(self) -> None:
        allowed = ("boolean", "int", "long", "float", "string", "contains")
        ordered = tuple(item for item in allowed if item in self.reads)
        if not ordered or len(self.reads) != len(set(self.reads)) or any(item not in allowed for item in self.reads):
            raise ValueError("invalid libxposed remote-preferences read selection")
        if self.capability_policy != "nullable-on-unsupported":
            raise ValueError("bounded libxposed remote preferences require nullable-on-unsupported capability policy")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed remote preferences require explicit propagate failure policy")
        object.__setattr__(self, "reads", ordered)


@dataclass(frozen=True, order=True)
class DexLibxposedRemoteFilesSpec:
    """Capability-gated API-102 remote file list/open helpers."""

    operations: tuple[str, ...]
    capability_policy: str = "nullable-on-unsupported"
    failure_policy: str = "propagate"

    def __post_init__(self) -> None:
        allowed = ("list", "open")
        ordered = tuple(item for item in allowed if item in self.operations)
        if not ordered or len(self.operations) != len(set(self.operations)) or any(item not in allowed for item in self.operations):
            raise ValueError("invalid libxposed remote-file operation selection")
        if self.capability_policy != "nullable-on-unsupported":
            raise ValueError("bounded libxposed remote files require nullable-on-unsupported capability policy")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed remote files require explicit propagate failure policy")
        object.__setattr__(self, "operations", ordered)


@dataclass(frozen=True, order=True)
class DexLibxposedHotReloadSpec:
    """API-102 stable-ID guarded single-hook atomic replacement policy."""

    hooker_class_descriptor: str
    policy: str = "single-retained-hook-id-guarded-atomic-replace"
    failure_policy: str = "propagate"
    hook_id: str = "xax.primary"
    mismatch_policy: str = "skip-replacement"
    state_policy: str = "package-ready-class-loader"
    missing_state_policy: str = "reject-reload"

    def __post_init__(self) -> None:
        _validate_class_descriptor(self.hooker_class_descriptor)
        if self.policy != "single-retained-hook-id-guarded-atomic-replace":
            raise ValueError("unsupported bounded libxposed hot-reload policy")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed hot reload requires explicit propagate failure policy")
        if not self.hook_id or "\x00" in self.hook_id or "\n" in self.hook_id or "\r" in self.hook_id:
            raise ValueError("libxposed hot-reload hook ID must be nonempty single-line text")
        if self.mismatch_policy != "skip-replacement":
            raise ValueError("bounded libxposed hot reload requires skip-replacement mismatch policy")
        if self.state_policy != "package-ready-class-loader":
            raise ValueError("bounded libxposed hot reload requires package-ready-class-loader state policy")
        if self.missing_state_policy != "reject-reload":
            raise ValueError("bounded libxposed hot reload requires reject-reload missing-state policy")


# Generic extension point for managed bodies (ADR-111).  A shape that needs new
# managed code supplies instructions with symbolic references; the emitter
# derives every pool entry from them, so no emitter change is needed per shape.
_ASSEMBLED_OPCODES = {
    "return-void": 0x0E, "move-result": 0x0A, "move-result-wide": 0x0B, "move-result-object": 0x0C,
    "const": 0x14, "const-string": 0x1A, "check-cast": 0x1F, "new-instance": 0x22,
    "invoke-virtual": 0x6E, "invoke-super": 0x6F, "invoke-direct": 0x70, "invoke-static": 0x71, "invoke-interface": 0x72,
}


@dataclass(frozen=True, order=True)
class DexMethodRef:
    class_descriptor: str
    name: str
    proto: DexProto


@dataclass(frozen=True, order=True)
class DexInstruction:
    """One instruction: ``registers`` in operand order; ``reference`` is a string, a type, or a ``DexMethodRef``."""

    mnemonic: str
    registers: tuple[int, ...] = ()
    reference: str | DexMethodRef | None = None
    literal: int | None = None

    def __post_init__(self) -> None:
        if self.mnemonic not in _ASSEMBLED_OPCODES:
            raise ValueError(f"unsupported assembled instruction {self.mnemonic}")
        if self.mnemonic.startswith("invoke-"):
            if not isinstance(self.reference, DexMethodRef) or not 0 <= len(self.registers) <= 5 or any(not 0 <= item <= 15 for item in self.registers):
                raise ValueError("invoke needs a method reference and at most five registers v0..v15")
        elif self.mnemonic in ("const-string", "check-cast", "new-instance"):
            if not isinstance(self.reference, str) or len(self.registers) != 1:
                raise ValueError(f"{self.mnemonic} needs one register and one reference")
            if self.mnemonic != "const-string":
                _validate_type_descriptor(self.reference, allow_void=False)
        elif self.mnemonic == "const":
            if len(self.registers) != 1 or self.literal is None or not -(1 << 31) <= self.literal < (1 << 32):
                raise ValueError("const needs one register and a 32-bit literal")
        elif self.mnemonic != "return-void" and len(self.registers) != 1:
            raise ValueError(f"{self.mnemonic} needs one register")
        if any(not 0 <= item <= 0xFF for item in self.registers):
            raise ValueError("assembled instructions address v0..v255")


@dataclass(frozen=True, order=True)
class DexAssembledMethod:
    """A method body given as instructions; parameters occupy the last registers, as DEX requires."""

    name: str
    proto: DexProto
    registers_size: int
    instructions: tuple[DexInstruction, ...]
    access_flags: int = ACC_PUBLIC

    def __post_init__(self) -> None:
        _validate_member_name(self.name)
        if self.access_flags & ACC_NATIVE or not self.instructions:
            raise ValueError("assembled method needs a body")
        if self.registers_size < self.ins_size or self.registers_size > 0xFFFF:
            raise ValueError("assembled method registers must hold its parameters")

    @property
    def ins_size(self) -> int:
        return int(not self.access_flags & ACC_STATIC) + sum(2 if item in ("J", "D") else 1 for item in self.proto.parameters)

    @property
    def outs_size(self) -> int:
        return max((len(item.registers) for item in self.instructions if item.mnemonic.startswith("invoke-")), default=0)

    @property
    def references(self) -> tuple:
        return tuple(item.reference for item in self.instructions if item.reference is not None)


def _assemble(method: DexAssembledMethod, string_idx, type_idx, method_idx) -> tuple[int, ...]:
    units: list[int] = []
    for item in method.instructions:
        opcode = _ASSEMBLED_OPCODES[item.mnemonic]
        if item.mnemonic.startswith("invoke-"):
            reference = item.reference
            index = method_idx[(reference.class_descriptor, reference.name, reference.proto)]
            registers = (*item.registers, 0, 0, 0, 0, 0)
            units += [(len(item.registers) << 12) | (registers[4] << 8) | opcode, index,
                      registers[0] | (registers[1] << 4) | (registers[2] << 8) | (registers[3] << 12)]
        elif item.mnemonic in ("const-string", "check-cast", "new-instance"):
            index = string_idx[item.reference] if item.mnemonic == "const-string" else type_idx[item.reference]
            units += [(item.registers[0] << 8) | opcode, index]
        elif item.mnemonic == "const":
            value = item.literal & 0xFFFFFFFF
            units += [(item.registers[0] << 8) | opcode, value & 0xFFFF, value >> 16]
        elif item.mnemonic == "return-void":
            units.append(opcode)
        else:
            units.append((item.registers[0] << 8) | opcode)
    if any(unit > 0xFFFF for unit in units):
        raise ValueError("assembled method index exceeds 16-bit DEX capacity")
    return tuple(units)


@dataclass(frozen=True)
class DexBridgeSpec:
    class_descriptor: str
    superclass_descriptor: str
    native_methods: tuple[DexNativeMethod, ...] = ()
    forwarding_overrides: tuple[DexForwardingOverride, ...] = ()
    interfaces: tuple[str, ...] = ()
    native_library: str | None = None
    class_access_flags: int = ACC_PUBLIC | ACC_SUPER
    activity_ui: DexActivityUiSpec | None = None
    click_text: DexClickTextSpec | None = None
    null_return_overrides: tuple[DexNullReturnOverride, ...] = ()
    native_library_load_override: str | None = None
    libxposed_hook_intercept: DexLibxposedHookInterceptSpec | None = None
    libxposed_hook_install: DexLibxposedHookInstallSpec | None = None
    libxposed_module_services: DexLibxposedModuleServicesSpec | None = None
    libxposed_remote_preferences: DexLibxposedRemotePreferencesSpec | None = None
    constant_string_methods: tuple[DexConstantStringMethod, ...] = ()
    echo_string_methods: tuple[DexEchoStringMethod, ...] = ()
    libxposed_hot_reload: DexLibxposedHotReloadSpec | None = None
    libxposed_remote_files: DexLibxposedRemoteFilesSpec | None = None
    assembled_methods: tuple[DexAssembledMethod, ...] = ()

    def __post_init__(self) -> None:
        _validate_class_descriptor(self.class_descriptor)
        assembled = tuple(sorted(self.assembled_methods, key=lambda item: (item.name, item.proto)))
        if len({(item.name, item.proto) for item in assembled}) != len(assembled):
            raise ValueError("duplicate assembled method")
        if {(item.name, item.proto) for item in assembled} & {(item.name, item.proto) for item in self.native_methods}:
            raise ValueError("assembled method duplicates a native method")
        object.__setattr__(self, "assembled_methods", assembled)
        _validate_class_descriptor(self.superclass_descriptor)
        if self.class_descriptor == self.superclass_descriptor:
            raise ValueError("bridge class cannot extend itself")
        methods = tuple(sorted(self.native_methods, key=lambda item: (item.name, item.proto)))
        if len({(item.name, item.proto) for item in methods}) != len(methods):
            raise ValueError("duplicate bridge native method")
        object.__setattr__(self, "native_methods", methods)
        overrides = tuple(sorted(self.forwarding_overrides, key=lambda item: (item.name, item.proto, item.native_target)))
        if len({(item.name, item.proto) for item in overrides}) != len(overrides):
            raise ValueError("duplicate forwarding override")
        object.__setattr__(self, "forwarding_overrides", overrides)
        null_overrides = tuple(sorted(self.null_return_overrides, key=lambda item: (item.name, item.proto)))
        if len({(item.name, item.proto) for item in null_overrides}) != len(null_overrides):
            raise ValueError("duplicate null-return override")
        occupied = {(item.name, item.proto) for item in overrides} | {(item.name, item.proto) for item in methods}
        if any((item.name, item.proto) in occupied for item in null_overrides):
            raise ValueError("null-return override duplicates another bridge method")
        object.__setattr__(self, "null_return_overrides", null_overrides)
        constant_methods = tuple(sorted(self.constant_string_methods, key=lambda item: (item.name, item.value)))
        if len({item.name for item in constant_methods}) != len(constant_methods):
            raise ValueError("duplicate constant string method")
        occupied_names = {item.name for item in methods} | {item.name for item in overrides} | {item.name for item in null_overrides}
        if any(item.name in occupied_names for item in constant_methods):
            raise ValueError("constant string method duplicates another bridge method")
        object.__setattr__(self, "constant_string_methods", constant_methods)
        echo_methods = tuple(sorted(self.echo_string_methods, key=lambda item: item.name))
        if len({item.name for item in echo_methods}) != len(echo_methods):
            raise ValueError("duplicate echo string method")
        if any(item.name in occupied_names or item.name in {value.name for value in constant_methods} for item in echo_methods):
            raise ValueError("echo string method duplicates another bridge method")
        object.__setattr__(self, "echo_string_methods", echo_methods)
        if self.libxposed_module_services is not None:
            service_names = {
                "framework-name": "xaxFrameworkName",
                "framework-version": "xaxFrameworkVersion",
                "remote-preferences": "xaxRemotePreferences",
                "list-remote-files": "xaxListRemoteFiles",
                "open-remote-file": "xaxOpenRemoteFile",
            }
            existing = occupied_names | {item.name for item in constant_methods} | {item.name for item in echo_methods}
            generated = {service_names[item] for item in self.libxposed_module_services.services}
            if generated & existing:
                raise ValueError("libxposed module-service helper duplicates another bridge method")
        if self.libxposed_remote_preferences is not None:
            preference_names = {
                "xaxRemotePreferencesIfSupported",
                *(f"xaxPref{item.title()}" for item in self.libxposed_remote_preferences.reads),
            }
            existing = occupied_names | {item.name for item in constant_methods} | {item.name for item in echo_methods}
            if preference_names & existing:
                raise ValueError("libxposed remote-preferences helper duplicates another bridge method")
        if self.libxposed_remote_files is not None:
            remote_file_names = set()
            if "list" in self.libxposed_remote_files.operations:
                remote_file_names.add("xaxListRemoteFilesIfSupported")
            if "open" in self.libxposed_remote_files.operations:
                remote_file_names.add("xaxOpenRemoteFileIfSupported")
            existing = occupied_names | {item.name for item in constant_methods} | {item.name for item in echo_methods}
            if remote_file_names & existing:
                raise ValueError("libxposed remote-file helper duplicates another bridge method")
        interfaces = tuple(sorted(set(self.interfaces)))
        for descriptor in interfaces:
            _validate_class_descriptor(descriptor)
            if descriptor in (self.class_descriptor, self.superclass_descriptor):
                raise ValueError("bridge interface must differ from class/superclass")
        object.__setattr__(self, "interfaces", interfaces)
        native_by_key = {(item.name, item.proto): item for item in methods}
        for item in overrides:
            target = native_by_key.get((item.native_target, item.proto))
            if target is None:
                raise ValueError("forwarding override target must name a native method with the same prototype")
            if not (target.access_flags & ACC_PRIVATE):
                raise ValueError("forwarding override target must be a private native method")
        if self.native_library is not None:
            if not self.native_library or any(ch in self.native_library for ch in "/\\\x00"):
                raise ValueError("native library name must be a nonempty base name")
        if self.native_library_load_override is not None:
            _validate_member_name(self.native_library_load_override)
            if self.native_library is None:
                raise ValueError("deferred native library load requires native_library")
            matches = [item for item in overrides if item.name == self.native_library_load_override]
            if len(matches) != 1 or matches[0].call_super:
                raise ValueError("deferred native library load requires one direct forwarding override")
        if self.activity_ui is not None:
            if self.superclass_descriptor != "Landroid/app/Activity;":
                raise ValueError("managed Activity UI setup requires android.app.Activity superclass")
            lifecycle = [item for item in overrides if item.name == "onCreate"]
            if len(lifecycle) != 1 or lifecycle[0].proto != DexProto("V", ("Landroid/os/Bundle;",)) or not lifecycle[0].call_super:
                raise ValueError("managed Activity UI setup requires lifecycle-correct onCreate(Bundle) override")
            if self.activity_ui.button_text_method_name is not None:
                constant_matching = [item for item in constant_methods if item.name == self.activity_ui.button_text_method_name]
                echo_matching = [item for item in echo_methods if item.name == self.activity_ui.button_text_method_name]
                if self.activity_ui.button_text_method_argument is None:
                    if len(constant_matching) != 1 or echo_matching:
                        raise ValueError("Activity zero-arg managed button-text source must name one constant string method")
                elif len(echo_matching) != 1 or constant_matching:
                    raise ValueError("Activity one-arg managed button-text source must name one echo string method")
        if self.click_text is not None:
            if self.superclass_descriptor != "Ljava/lang/Object;" or "Landroid/view/View$OnClickListener;" not in interfaces:
                raise ValueError("managed click text mutation requires a View.OnClickListener adapter")
            click = [item for item in overrides if item.name == "onClick"]
            expected = DexProto("V", ("Landroid/view/View;",))
            if len(click) != 1 or click[0].proto != expected or click[0].call_super:
                raise ValueError("managed click text mutation requires direct onClick(View) forwarding")
        if self.libxposed_hook_intercept is not None:
            hooker = "Lio/github/libxposed/api/XposedInterface$Hooker;"
            if self.superclass_descriptor != "Ljava/lang/Object;" or hooker not in interfaces:
                raise ValueError("libxposed hook interceptor requires XposedInterface.Hooker on java.lang.Object")
            if self.native_methods or self.forwarding_overrides or self.null_return_overrides:
                raise ValueError("bounded libxposed hook interceptor cannot mix bridge/native methods")
            if self.native_library is not None or self.activity_ui is not None or self.click_text is not None:
                raise ValueError("bounded libxposed hook interceptor has no native library or Android UI lowering")
        if self.libxposed_hook_install is not None:
            if self.superclass_descriptor != "Lio/github/libxposed/api/XposedModule;":
                raise ValueError("libxposed hook installation requires XposedModule superclass")
            package_ready = [item for item in overrides if item.name == "onPackageReady"]
            expected = DexProto("V", ("Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;",))
            if len(package_ready) != 1 or package_ready[0].proto != expected or package_ready[0].call_super:
                raise ValueError("libxposed hook installation requires direct onPackageReady(PackageReadyParam) forwarding")
            if self.libxposed_hook_install.hooker_class_descriptor == self.class_descriptor:
                raise ValueError("libxposed hooker class must differ from module entry class")
        if self.libxposed_hot_reload is not None:
            if self.libxposed_hook_install is None:
                raise ValueError("bounded libxposed hot reload requires hook installation")
            if self.libxposed_hook_install.lifetime_policy != "retained-manual-unhook":
                raise ValueError("bounded libxposed hot reload requires retained-manual-unhook lifetime")
            if self.libxposed_hot_reload.hooker_class_descriptor != self.libxposed_hook_install.hooker_class_descriptor:
                raise ValueError("libxposed hot-reload hooker must equal installed hooker")
            if self.libxposed_hook_install.hook_id != self.libxposed_hot_reload.hook_id:
                raise ValueError("libxposed hot-reload hook ID must equal installed hook ID")
            existing = occupied_names | {item.name for item in constant_methods} | {item.name for item in echo_methods}
            if {"onHotReloading", "onHotReloaded"} & existing:
                raise ValueError("libxposed hot-reload callback duplicates another bridge method")


@dataclass(frozen=True)
class DexInspection:
    version: str
    file_size: int
    string_ids_size: int
    type_ids_size: int
    proto_ids_size: int
    method_ids_size: int
    class_defs_size: int
    data_size: int
    map_items: tuple[tuple[int, int, int], ...]
    strings: tuple[str, ...]
    class_descriptor: str
    superclass_descriptor: str
    interfaces: tuple[str, ...]
    checksum_valid: bool
    signature_valid: bool


def activity_bridge_spec(
    class_descriptor: str = "Lxax/generated/XaxActivity;",
    *,
    lifecycle_method: str = "onCreate",
) -> DexBridgeSpec:
    """Return the minimum Activity bridge shape needed for native lifecycle entry."""

    proto = DexProto("V", ("Landroid/os/Bundle;",))
    native_name = f"xax{lifecycle_method[0].upper()}{lifecycle_method[1:]}"
    return DexBridgeSpec(
        class_descriptor,
        "Landroid/app/Activity;",
        (DexNativeMethod(native_name, proto, ACC_PRIVATE | ACC_NATIVE),),
        (DexForwardingOverride(lifecycle_method, proto, native_name, ACC_PROTECTED),),
        native_library="xaxapp",
    )




def interface_callback_bridge_spec(
    class_descriptor: str,
    interface_descriptor: str,
    method_name: str,
    proto: DexProto,
    *,
    native_library: str = "xaxapp",
) -> DexBridgeSpec:
    """Synthesize one allocation-free managed interface callback adapter.

    The generated virtual method performs only ``invoke-direct`` to a private
    native method followed by ``return-void``.  Instantiation/allocation of the
    adapter itself is a separate explicit platform action.
    """
    if proto.return_type != "V":
        raise ValueError("interface callback bridge currently requires void result")
    native_name = f"xax{method_name[0].upper()}{method_name[1:]}" if method_name else ""
    return DexBridgeSpec(
        class_descriptor,
        "Ljava/lang/Object;",
        (DexNativeMethod(native_name, proto, ACC_PRIVATE | ACC_NATIVE),),
        (DexForwardingOverride(method_name, proto, native_name, ACC_PUBLIC, False),),
        (interface_descriptor,),
        native_library,
    )


def click_text_listener_bridge_spec(
    class_descriptor: str = "Lxax/generated/XaxOnClickListener;",
    *,
    text: str = "Clicked",
    native_library: str | None = None,
) -> DexBridgeSpec:
    """Generate an OnClickListener that updates the clicked TextView then calls XAX."""

    base = interface_callback_bridge_spec(
        class_descriptor,
        "Landroid/view/View$OnClickListener;",
        "onClick",
        DexProto("V", ("Landroid/view/View;",)),
        native_library=native_library,
    )
    return DexBridgeSpec(
        base.class_descriptor,
        base.superclass_descriptor,
        base.native_methods,
        base.forwarding_overrides,
        base.interfaces,
        base.native_library,
        base.class_access_flags,
        base.activity_ui,
        DexClickTextSpec(text),
    )


def click_resource_listener_bridge_spec(
    class_descriptor: str = "Lxax/generated/XaxOnClickListener;",
    *,
    text_resource_id: int,
    native_library: str | None = None,
) -> DexBridgeSpec:
    """Generate an OnClickListener that sets one exact string resource ID then calls XAX."""

    base = interface_callback_bridge_spec(
        class_descriptor,
        "Landroid/view/View$OnClickListener;",
        "onClick",
        DexProto("V", ("Landroid/view/View;",)),
        native_library=native_library,
    )
    return DexBridgeSpec(
        base.class_descriptor,
        base.superclass_descriptor,
        base.native_methods,
        base.forwarding_overrides,
        base.interfaces,
        base.native_library,
        base.class_access_flags,
        base.activity_ui,
        DexClickTextSpec(text_resource_id=text_resource_id),
    )


def activity_button_bridge_spec(
    class_descriptor: str = "Lxax/generated/XaxActivity;",
    *,
    listener_class_descriptor: str = "Lxax/generated/XaxOnClickListener;",
    button_text: str = "XAX",
) -> DexBridgeSpec:
    """Activity bridge that performs the first bounded managed UI setup.

    ``onCreate`` calls ``super``, creates one ``Button``, sets its initial text,
    creates/registers the generated listener, installs the button as the content
    view, then crosses into native XAX once for the lifecycle callback.
    """

    base = activity_bridge_spec(class_descriptor)
    return DexBridgeSpec(
        base.class_descriptor,
        base.superclass_descriptor,
        base.native_methods,
        base.forwarding_overrides,
        base.interfaces,
        base.native_library,
        base.class_access_flags,
        DexActivityUiSpec(listener_class_descriptor, button_text),
    )

def activity_button_resource_bridge_spec(
    class_descriptor: str = "Lxax/generated/XaxActivity;",
    *,
    listener_class_descriptor: str = "Lxax/generated/XaxOnClickListener;",
    button_text_resource_id: int,
) -> DexBridgeSpec:
    """Activity bridge whose initial Button text is loaded by exact Android resource ID."""

    base = activity_bridge_spec(class_descriptor)
    return DexBridgeSpec(
        base.class_descriptor,
        base.superclass_descriptor,
        base.native_methods,
        base.forwarding_overrides,
        base.interfaces,
        base.native_library,
        base.class_access_flags,
        DexActivityUiSpec(listener_class_descriptor, button_text_resource_id=button_text_resource_id),
    )


def _validate_member_name(value: str) -> None:
    if not value or "\x00" in value or "/" in value or "." in value or ";" in value or "[" in value:
        raise ValueError(f"invalid DEX member name: {value!r}")


def _validate_class_descriptor(value: str) -> None:
    if not (value.startswith("L") and value.endswith(";") and len(value) > 2):
        raise ValueError(f"invalid DEX class descriptor: {value!r}")
    if "." in value or "\x00" in value or "//" in value:
        raise ValueError(f"invalid DEX class descriptor: {value!r}")


def _validate_type_descriptor(value: str, *, allow_void: bool) -> None:
    if value == "V":
        if allow_void:
            return
        raise ValueError("void is not a valid field/parameter type")
    if value in {"Z", "B", "S", "C", "I", "J", "F", "D"}:
        return
    if value.startswith("["):
        if len(value) > 256:
            raise ValueError("DEX array descriptor exceeds 255 dimensions")
        _validate_type_descriptor(value.lstrip("["), allow_void=False)
        return
    _validate_class_descriptor(value)


def _uleb(value: int) -> bytes:
    if value < 0:
        raise ValueError("uleb128 requires a nonnegative value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    start = offset
    while True:
        if offset >= len(data) or shift >= 35:
            raise ValueError("malformed uleb128")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if _uleb(value) != data[start:offset]:
                raise ValueError("non-canonical uleb128")
            return value, offset
        shift += 7


def _utf16_units(value: str) -> tuple[int, ...]:
    raw = value.encode("utf-16-le", "surrogatepass")
    return tuple(struct.unpack_from("<H", raw, index)[0] for index in range(0, len(raw), 2))


def _mutf8(value: str) -> bytes:
    out = bytearray()
    for code in _utf16_units(value):
        if code == 0:
            out.extend(b"\xC0\x80")
        elif code <= 0x7F:
            out.append(code)
        elif code <= 0x7FF:
            out.extend((0xC0 | (code >> 6), 0x80 | (code & 0x3F)))
        else:
            out.extend((0xE0 | (code >> 12), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F)))
    return bytes(out)


def _mutf8_decode(raw: bytes, expected_units: int) -> str:
    units: list[int] = []
    index = 0
    while index < len(raw):
        byte = raw[index]
        if byte <= 0x7F:
            if byte == 0:
                raise ValueError("embedded zero in MUTF-8")
            units.append(byte)
            index += 1
        elif byte & 0xE0 == 0xC0:
            if index + 1 >= len(raw):
                raise ValueError("truncated MUTF-8")
            units.append(((byte & 0x1F) << 6) | (raw[index + 1] & 0x3F))
            index += 2
        elif byte & 0xF0 == 0xE0:
            if index + 2 >= len(raw):
                raise ValueError("truncated MUTF-8")
            units.append(((byte & 0x0F) << 12) | ((raw[index + 1] & 0x3F) << 6) | (raw[index + 2] & 0x3F))
            index += 3
        else:
            raise ValueError("unsupported MUTF-8 leading byte")
    if len(units) != expected_units:
        raise ValueError("MUTF-8 UTF-16 length mismatch")
    packed = b"".join(struct.pack("<H", item) for item in units)
    return packed.decode("utf-16-le", "surrogatepass")


def _shorty(proto: DexProto) -> str:
    def item(value: str) -> str:
        return "L" if value.startswith(("L", "[")) else value

    return item(proto.return_type) + "".join(item(value) for value in proto.parameters)


def _align(buffer: bytearray, alignment: int = 4) -> None:
    buffer.extend(b"\x00" * ((-len(buffer)) % alignment))


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def emit_dex039_bridge(spec: DexBridgeSpec) -> bytes:
    """Emit a canonical DEX 039 file for *spec*.

    The generated constructor invokes ``super.<init>()`` directly.  If
    ``native_library`` is present, a generated ``<clinit>`` executes exactly one
    ``System.loadLibrary`` before any instance callback can run.  Native methods
    contain no code item, as required by DEX.
    """

    constructor_proto = DexProto("V", ())
    load_library_proto = DexProto("V", ("Ljava/lang/String;",))
    has_library_load = spec.native_library is not None
    has_clinit = has_library_load and spec.native_library_load_override is None
    activity_ui = spec.activity_ui
    click_text = spec.click_text
    hook_intercept = spec.libxposed_hook_intercept
    hook_install = spec.libxposed_hook_install
    module_services = spec.libxposed_module_services
    remote_preferences = spec.libxposed_remote_preferences
    hot_reload = spec.libxposed_hot_reload
    remote_files = spec.libxposed_remote_files
    button_ctor_proto = DexProto("V", ("Landroid/content/Context;",))
    set_text_proto = DexProto("V", ("Ljava/lang/CharSequence;",))
    set_text_resource_proto = DexProto("V", ("I",))
    activity_set_text_proto = set_text_resource_proto if activity_ui is not None and activity_ui.button_text_resource_id is not None else set_text_proto
    click_set_text_proto = set_text_resource_proto if click_text is not None and click_text.text_resource_id is not None else set_text_proto
    set_listener_proto = DexProto("V", ("Landroid/view/View$OnClickListener;",))
    set_content_view_proto = DexProto("V", ("Landroid/view/View;",))
    libxposed_chain = "Lio/github/libxposed/api/XposedInterface$Chain;"
    object_type = "Ljava/lang/Object;"
    hook_intercept_proto = DexProto(object_type, (libxposed_chain,))
    hook_get_arg_proto = DexProto(object_type, ("I",))
    hook_proceed_proto = DexProto(object_type, ())
    hook_proceed_args_proto = DexProto(object_type, ("[Ljava/lang/Object;",))
    libxposed_package_ready = "Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;"
    libxposed_hot_reloading = "Lio/github/libxposed/api/XposedModuleInterface$HotReloadingParam;"
    libxposed_hot_reloaded = "Lio/github/libxposed/api/XposedModuleInterface$HotReloadedParam;"
    libxposed_wrapper = "Lio/github/libxposed/api/XposedInterfaceWrapper;"
    libxposed_hook_builder = "Lio/github/libxposed/api/XposedInterface$HookBuilder;"
    libxposed_hooker = "Lio/github/libxposed/api/XposedInterface$Hooker;"
    libxposed_hook_handle = "Lio/github/libxposed/api/XposedInterface$HookHandle;"
    libxposed_exception_mode = "Lio/github/libxposed/api/XposedInterface$ExceptionMode;"
    class_loader_type = "Ljava/lang/ClassLoader;"
    class_type = "Ljava/lang/Class;"
    class_array_type = "[Ljava/lang/Class;"
    string_type = "Ljava/lang/String;"
    method_type = "Ljava/lang/reflect/Method;"
    executable_type = "Ljava/lang/reflect/Executable;"
    shared_preferences_type = "Landroid/content/SharedPreferences;"
    list_type = "Ljava/util/List;"
    parcel_file_descriptor_type = "Landroid/os/ParcelFileDescriptor;"
    string_array_type = "[Ljava/lang/String;"
    get_class_loader_proto = DexProto(class_loader_type, ())
    load_class_proto = DexProto(class_type, (string_type,))
    get_declared_method_proto = DexProto(method_type, (string_type, class_array_type))
    hook_proto = DexProto(libxposed_hook_builder, (executable_type,))
    deoptimize_proto = DexProto("Z", (executable_type,))
    set_exception_mode_proto = DexProto(libxposed_hook_builder, (libxposed_exception_mode,))
    set_id_proto = DexProto(libxposed_hook_builder, (string_type,))
    intercept_builder_proto = DexProto(libxposed_hook_handle, (libxposed_hooker,))
    hot_reloading_proto = DexProto("Z", (libxposed_hot_reloading,))
    hot_reloaded_proto = DexProto("V", (libxposed_hot_reloaded,))
    set_saved_instance_state_proto = DexProto("V", (object_type,))
    get_saved_instance_state_proto = DexProto(object_type, ())
    old_hook_handles_proto = DexProto(list_type, ())
    list_get_proto = DexProto(object_type, ("I",))
    list_is_empty_proto = DexProto("Z", ())
    get_hook_id_proto = DexProto(string_type, ())
    string_equals_proto = DexProto("Z", (object_type,))
    replace_hook_proto = DexProto(libxposed_hook_handle, (libxposed_hooker,))
    module_service_methods = {
        "framework-name": ("xaxFrameworkName", "getFrameworkName", DexProto(string_type, ())),
        "framework-version": ("xaxFrameworkVersion", "getFrameworkVersion", DexProto(string_type, ())),
        "remote-preferences": ("xaxRemotePreferences", "getRemotePreferences", DexProto(shared_preferences_type, (string_type,))),
        "list-remote-files": ("xaxListRemoteFiles", "listRemoteFiles", DexProto(string_array_type, ())),
        "open-remote-file": ("xaxOpenRemoteFile", "openRemoteFile", DexProto(parcel_file_descriptor_type, (string_type,))),
    }
    framework_properties_proto = DexProto("J", ())
    remote_preferences_proto = DexProto(shared_preferences_type, (string_type,))
    list_remote_files_proto = DexProto(string_array_type, ())
    open_remote_file_proto = DexProto(parcel_file_descriptor_type, (string_type,))
    remote_preference_methods = {
        "boolean": (
            "xaxPrefBoolean", "getBoolean",
            DexProto("Z", (shared_preferences_type, string_type, "Z")),
            DexProto("Z", (string_type, "Z")),
        ),
        "int": (
            "xaxPrefInt", "getInt",
            DexProto("I", (shared_preferences_type, string_type, "I")),
            DexProto("I", (string_type, "I")),
        ),
        "long": (
            "xaxPrefLong", "getLong",
            DexProto("J", (shared_preferences_type, string_type, "J")),
            DexProto("J", (string_type, "J")),
        ),
        "float": (
            "xaxPrefFloat", "getFloat",
            DexProto("F", (shared_preferences_type, string_type, "F")),
            DexProto("F", (string_type, "F")),
        ),
        "string": (
            "xaxPrefString", "getString",
            DexProto(string_type, (shared_preferences_type, string_type, string_type)),
            DexProto(string_type, (string_type, string_type)),
        ),
        "contains": (
            "xaxPrefContains", "contains",
            DexProto("Z", (shared_preferences_type, string_type)),
            DexProto("Z", (string_type,)),
        ),
    }
    all_protos = {
        constructor_proto,
        *(item.proto for item in spec.native_methods),
        *(item.proto for item in spec.forwarding_overrides),
        *(item.proto for item in spec.null_return_overrides),
        *(item.proto for item in spec.constant_string_methods),
        *(item.proto for item in spec.echo_string_methods),
        *(item.proto for item in spec.assembled_methods),
        *(reference.proto for item in spec.assembled_methods for reference in item.references if isinstance(reference, DexMethodRef)),
    }
    if has_library_load:
        all_protos.add(load_library_proto)
    if activity_ui is not None:
        all_protos.update((button_ctor_proto, activity_set_text_proto, set_listener_proto, set_content_view_proto))
    if click_text is not None:
        all_protos.add(click_set_text_proto)
    if hook_intercept is not None:
        all_protos.update((hook_intercept_proto, hook_proceed_proto))
        if hook_intercept.inspected_argument_index is not None:
            all_protos.add(hook_get_arg_proto)
        if hook_intercept.argument_replacement_string is not None:
            all_protos.add(hook_proceed_args_proto)
    if hook_install is not None:
        all_protos.update((
            get_class_loader_proto,
            load_class_proto,
            get_declared_method_proto,
            hook_proto,
            set_exception_mode_proto,
            intercept_builder_proto,
        ))
        if hook_install.deoptimize_before_hook:
            all_protos.add(deoptimize_proto)
        if hook_install.hook_id is not None:
            all_protos.add(set_id_proto)
    if module_services is not None:
        all_protos.update(module_service_methods[item][2] for item in module_services.services)
    if remote_preferences is not None:
        all_protos.update((framework_properties_proto, remote_preferences_proto))
        for item in remote_preferences.reads:
            _, _, generated_proto, interface_proto = remote_preference_methods[item]
            all_protos.update((generated_proto, interface_proto))
    if hot_reload is not None:
        all_protos.update((
            hot_reloading_proto, hot_reloaded_proto, set_saved_instance_state_proto, get_saved_instance_state_proto,
            old_hook_handles_proto, list_get_proto, list_is_empty_proto, get_hook_id_proto, string_equals_proto, replace_hook_proto,
        ))
    if remote_files is not None:
        all_protos.add(framework_properties_proto)
        if "list" in remote_files.operations:
            all_protos.add(list_remote_files_proto)
        if "open" in remote_files.operations:
            all_protos.add(open_remote_file_proto)

    strings = {
        spec.class_descriptor,
        spec.superclass_descriptor,
        *spec.interfaces,
        "<init>",
        *(item.name for item in spec.native_methods),
        *(item.name for item in spec.forwarding_overrides),
        *(item.name for item in spec.null_return_overrides),
        *(item.name for item in spec.constant_string_methods),
        *(item.value for item in spec.constant_string_methods),
        *(item.name for item in spec.echo_string_methods),
        *(item.name for item in spec.assembled_methods),
        *(reference.name if isinstance(reference, DexMethodRef) else reference for item in spec.assembled_methods for reference in item.references),
        *(reference.class_descriptor for item in spec.assembled_methods for reference in item.references if isinstance(reference, DexMethodRef)),
        *(proto.return_type for proto in all_protos),
        *(param for proto in all_protos for param in proto.parameters),
        *(_shorty(proto) for proto in all_protos),
    }
    if has_library_load:
        strings.update(("Ljava/lang/System;", "loadLibrary", spec.native_library or ""))
    if has_clinit:
        strings.add("<clinit>")
    if activity_ui is not None:
        strings.update((
            activity_ui.listener_class_descriptor,
            "Landroid/content/Context;",
            "Landroid/view/View;",
            "Landroid/view/View$OnClickListener;",
            "Landroid/widget/Button;",
            "Landroid/widget/TextView;",
            "setText",
            "setOnClickListener",
            "setContentView",
        ))
        if activity_ui.button_text is not None:
            strings.update((activity_ui.button_text, "Ljava/lang/CharSequence;"))
        if activity_ui.button_text_method_argument is not None:
            strings.add(activity_ui.button_text_method_argument)
    if click_text is not None:
        strings.update(("Landroid/widget/TextView;", "setText"))
        if click_text.text is not None:
            strings.update((click_text.text, "Ljava/lang/CharSequence;"))
    if hook_intercept is not None:
        strings.update((libxposed_chain, object_type, "intercept", "proceed"))
        if hook_intercept.inspected_argument_index is not None:
            strings.add("getArg")
        if hook_intercept.replacement_string is not None:
            strings.add(hook_intercept.replacement_string)
        if hook_intercept.argument_replacement_string is not None:
            strings.add(hook_intercept.argument_replacement_string)
    if hook_install is not None:
        strings.update((
            libxposed_package_ready,
            libxposed_wrapper,
            libxposed_hook_builder,
            libxposed_hooker,
            libxposed_hook_handle,
            libxposed_exception_mode,
            class_loader_type,
            class_type,
            class_array_type,
            string_type,
            method_type,
            executable_type,
            hook_install.hooker_class_descriptor,
            hook_install.target_class_binary_name,
            hook_install.target_method_name,
            *hook_install.parameter_type_binary_names,
            "getClassLoader",
            "loadClass",
            "getDeclaredMethod",
            "hook",
            *( ("deoptimize",) if hook_install.deoptimize_before_hook else () ),
            "setExceptionMode",
            *( ("setId", hook_install.hook_id) if hook_install.hook_id is not None else () ),
            "intercept",
            hook_install.exception_mode,
        ))
        if hook_install.lifetime_policy == "retained-manual-unhook":
            strings.update(("xaxHookHandle", "xaxUnhook", "unhook"))
    if module_services is not None:
        strings.add(libxposed_wrapper)
        for service in module_services.services:
            generated_name, framework_name, _ = module_service_methods[service]
            strings.update((generated_name, framework_name))
    if remote_preferences is not None:
        strings.update((
            libxposed_wrapper,
            shared_preferences_type,
            "xaxRemotePreferencesIfSupported",
            "getFrameworkProperties",
            "getRemotePreferences",
        ))
        for item in remote_preferences.reads:
            generated_name, interface_name, _, _ = remote_preference_methods[item]
            strings.update((generated_name, interface_name))
    if hot_reload is not None:
        strings.update((
            libxposed_hot_reloading, libxposed_hot_reloaded, libxposed_hook_handle,
            libxposed_hooker, list_type, object_type, hot_reload.hooker_class_descriptor,
            "onHotReloading", "onHotReloaded", "setSavedInstanceState", "getSavedInstanceState",
            "getOldHookHandles", "get", "isEmpty", "getId", "equals", hot_reload.hook_id,
            "replaceHook", "xaxHookHandle", "xaxReloadClassLoader",
        ))
    if remote_files is not None:
        strings.update((libxposed_wrapper, "getFrameworkProperties"))
        if "list" in remote_files.operations:
            strings.update((string_array_type, "xaxListRemoteFilesIfSupported", "listRemoteFiles"))
        if "open" in remote_files.operations:
            strings.update((parcel_file_descriptor_type, string_type, "xaxOpenRemoteFileIfSupported", "openRemoteFile"))
    strings_ordered = tuple(sorted(strings, key=_utf16_units))
    string_idx = {value: index for index, value in enumerate(strings_ordered)}

    type_descriptors = {
        spec.class_descriptor,
        spec.superclass_descriptor,
        *spec.interfaces,
        *(proto.return_type for proto in all_protos),
        *(param for proto in all_protos for param in proto.parameters),
    }
    for item in spec.assembled_methods:
        for reference, instruction in zip(item.references, (entry for entry in item.instructions if entry.reference is not None)):
            if isinstance(reference, DexMethodRef):
                type_descriptors.add(reference.class_descriptor)
            elif instruction.mnemonic != "const-string":
                type_descriptors.add(reference)
    if has_library_load:
        type_descriptors.add("Ljava/lang/System;")
    if activity_ui is not None:
        type_descriptors.update((
            activity_ui.listener_class_descriptor,
            "Landroid/content/Context;",
            "Landroid/view/View;",
            "Landroid/view/View$OnClickListener;",
            "Landroid/widget/Button;",
            "Landroid/widget/TextView;",
        ))
        if activity_ui.button_text is not None:
            type_descriptors.add("Ljava/lang/CharSequence;")
    if click_text is not None:
        type_descriptors.add("Landroid/widget/TextView;")
        if click_text.text is not None:
            type_descriptors.add("Ljava/lang/CharSequence;")
    if hook_intercept is not None:
        type_descriptors.update((libxposed_chain, object_type))
        if hook_intercept.argument_replacement_string is not None:
            type_descriptors.add("[Ljava/lang/Object;")
    if hook_install is not None:
        type_descriptors.update((
            libxposed_package_ready,
            libxposed_wrapper,
            libxposed_hook_builder,
            libxposed_hooker,
            libxposed_hook_handle,
            libxposed_exception_mode,
            class_loader_type,
            class_type,
            class_array_type,
            string_type,
            method_type,
            executable_type,
            hook_install.hooker_class_descriptor,
        ))
    if module_services is not None:
        type_descriptors.add(libxposed_wrapper)
    if remote_preferences is not None:
        type_descriptors.update((libxposed_wrapper, shared_preferences_type))
    if hot_reload is not None:
        type_descriptors.update((
            libxposed_hot_reloading, libxposed_hot_reloaded, libxposed_hook_handle,
            libxposed_hooker, list_type, object_type, hot_reload.hooker_class_descriptor,
        ))
    if remote_files is not None:
        type_descriptors.add(libxposed_wrapper)
        if "list" in remote_files.operations:
            type_descriptors.add(string_array_type)
        if "open" in remote_files.operations:
            type_descriptors.update((parcel_file_descriptor_type, string_type))
    types_ordered = tuple(sorted(type_descriptors, key=lambda value: string_idx[value]))
    type_idx = {value: index for index, value in enumerate(types_ordered)}

    protos_ordered = tuple(
        sorted(
            all_protos,
            key=lambda proto: (
                type_idx[proto.return_type],
                tuple(type_idx[value] for value in proto.parameters),
            ),
        )
    )
    proto_idx = {value: index for index, value in enumerate(protos_ordered)}

    method_keys = {
        (spec.superclass_descriptor, "<init>", constructor_proto),
        (spec.class_descriptor, "<init>", constructor_proto),
        *((spec.class_descriptor, item.name, item.proto) for item in spec.native_methods),
        *((spec.class_descriptor, item.name, item.proto) for item in spec.forwarding_overrides),
        *((spec.class_descriptor, item.name, item.proto) for item in spec.null_return_overrides),
        *((spec.class_descriptor, item.name, item.proto) for item in spec.constant_string_methods),
        *((spec.class_descriptor, item.name, item.proto) for item in spec.echo_string_methods),
        *((spec.superclass_descriptor, item.name, item.proto) for item in spec.forwarding_overrides if item.call_super),
        *((spec.class_descriptor, item.name, item.proto) for item in spec.assembled_methods),
        *((reference.class_descriptor, reference.name, reference.proto) for item in spec.assembled_methods for reference in item.references if isinstance(reference, DexMethodRef)),
    }
    if has_library_load:
        method_keys.add(("Ljava/lang/System;", "loadLibrary", load_library_proto))
    if has_clinit:
        method_keys.add((spec.class_descriptor, "<clinit>", constructor_proto))
    if activity_ui is not None:
        method_keys.update((
            ("Landroid/widget/Button;", "<init>", button_ctor_proto),
            ("Landroid/widget/TextView;", "setText", activity_set_text_proto),
            (activity_ui.listener_class_descriptor, "<init>", constructor_proto),
            ("Landroid/view/View;", "setOnClickListener", set_listener_proto),
            ("Landroid/app/Activity;", "setContentView", set_content_view_proto),
        ))
    if click_text is not None:
        method_keys.add(("Landroid/widget/TextView;", "setText", click_set_text_proto))
    if hook_intercept is not None:
        method_keys.update(((spec.class_descriptor, "intercept", hook_intercept_proto), (libxposed_chain, "proceed", hook_proceed_proto)))
        if hook_intercept.inspected_argument_index is not None:
            method_keys.add((libxposed_chain, "getArg", hook_get_arg_proto))
        if hook_intercept.argument_replacement_string is not None:
            method_keys.add((libxposed_chain, "proceed", hook_proceed_args_proto))
    if hook_install is not None:
        method_keys.update((
            (libxposed_package_ready, "getClassLoader", get_class_loader_proto),
            (class_loader_type, "loadClass", load_class_proto),
            (class_type, "getDeclaredMethod", get_declared_method_proto),
            (libxposed_wrapper, "hook", hook_proto),
            (libxposed_hook_builder, "setExceptionMode", set_exception_mode_proto),
            (libxposed_hook_builder, "intercept", intercept_builder_proto),
            (hook_install.hooker_class_descriptor, "<init>", constructor_proto),
        ))
        if hook_install.hook_id is not None:
            method_keys.add((libxposed_hook_builder, "setId", set_id_proto))
        if hook_install.deoptimize_before_hook:
            method_keys.add((libxposed_wrapper, "deoptimize", deoptimize_proto))
        if hook_install.lifetime_policy == "retained-manual-unhook":
            method_keys.update((
                (spec.class_descriptor, "xaxUnhook", constructor_proto),
                (libxposed_hook_handle, "unhook", constructor_proto),
            ))
    if module_services is not None:
        for service in module_services.services:
            generated_name, framework_name, proto = module_service_methods[service]
            method_keys.add((spec.class_descriptor, generated_name, proto))
            method_keys.add((libxposed_wrapper, framework_name, proto))
    if remote_preferences is not None:
        method_keys.update((
            (spec.class_descriptor, "xaxRemotePreferencesIfSupported", remote_preferences_proto),
            (libxposed_wrapper, "getFrameworkProperties", framework_properties_proto),
            (libxposed_wrapper, "getRemotePreferences", remote_preferences_proto),
        ))
        for item in remote_preferences.reads:
            generated_name, interface_name, generated_proto, interface_proto = remote_preference_methods[item]
            method_keys.add((spec.class_descriptor, generated_name, generated_proto))
            method_keys.add((shared_preferences_type, interface_name, interface_proto))
    if hot_reload is not None:
        method_keys.update((
            (spec.class_descriptor, "onHotReloading", hot_reloading_proto),
            (spec.class_descriptor, "onHotReloaded", hot_reloaded_proto),
            (libxposed_hot_reloading, "setSavedInstanceState", set_saved_instance_state_proto),
            (libxposed_hot_reloaded, "getSavedInstanceState", get_saved_instance_state_proto),
            (libxposed_hot_reloaded, "getOldHookHandles", old_hook_handles_proto),
            (list_type, "get", list_get_proto),
            (list_type, "isEmpty", list_is_empty_proto),
            (libxposed_hook_handle, "getId", get_hook_id_proto),
            (string_type, "equals", string_equals_proto),
            (hot_reload.hooker_class_descriptor, "<init>", constructor_proto),
            (libxposed_hook_handle, "replaceHook", replace_hook_proto),
        ))
    if remote_files is not None:
        method_keys.add((libxposed_wrapper, "getFrameworkProperties", framework_properties_proto))
        if "list" in remote_files.operations:
            method_keys.update((
                (spec.class_descriptor, "xaxListRemoteFilesIfSupported", list_remote_files_proto),
                (libxposed_wrapper, "listRemoteFiles", list_remote_files_proto),
            ))
        if "open" in remote_files.operations:
            method_keys.update((
                (spec.class_descriptor, "xaxOpenRemoteFileIfSupported", open_remote_file_proto),
                (libxposed_wrapper, "openRemoteFile", open_remote_file_proto),
            ))
    methods_ordered = tuple(
        sorted(
            method_keys,
            key=lambda item: (type_idx[item[0]], string_idx[item[1]], proto_idx[item[2]]),
        )
    )
    method_idx = {value: index for index, value in enumerate(methods_ordered)}

    field_keys: set[tuple[str, str, str]] = set()
    if hook_install is not None:
        field_keys.add((libxposed_exception_mode, hook_install.exception_mode, libxposed_exception_mode))
        if hook_install.lifetime_policy == "retained-manual-unhook":
            field_keys.add((spec.class_descriptor, "xaxHookHandle", libxposed_hook_handle))
    if hot_reload is not None:
        field_keys.add((spec.class_descriptor, "xaxReloadClassLoader", class_loader_type))
    fields_ordered = tuple(sorted(field_keys, key=lambda item: (type_idx[item[0]], string_idx[item[1]], type_idx[item[2]])))
    field_idx = {value: index for index, value in enumerate(fields_ordered)}

    string_ids_off = DEX_HEADER_SIZE if strings_ordered else 0
    type_ids_off = string_ids_off + 4 * len(strings_ordered) if types_ordered else 0
    proto_ids_off = type_ids_off + 4 * len(types_ordered) if protos_ordered else 0
    field_ids_off = proto_ids_off + 12 * len(protos_ordered) if fields_ordered else 0
    method_ids_base = (field_ids_off + 8 * len(fields_ordered)) if fields_ordered else (proto_ids_off + 12 * len(protos_ordered))
    method_ids_off = method_ids_base if methods_ordered else 0
    class_defs_off = method_ids_off + 8 * len(methods_ordered)
    data_off = class_defs_off + 32
    if data_off % 4:
        raise AssertionError("fixed DEX sections lost 4-byte alignment")

    data = bytearray()
    type_list_values = {proto.parameters for proto in protos_ordered if proto.parameters}
    if spec.interfaces:
        type_list_values.add(spec.interfaces)
    type_list_offsets_by_values: dict[tuple[str, ...], int] = {}
    type_list_offsets: list[int] = []
    for values in sorted(
        type_list_values,
        key=lambda items: tuple(type_idx[item] for item in items),
    ):
        _align(data)
        offset = data_off + len(data)
        type_list_offsets_by_values[values] = offset
        type_list_offsets.append(offset)
        data.extend(_u32(len(values)))
        data.extend(b"".join(_u16(type_idx[item]) for item in values))
    parameter_offsets = type_list_offsets_by_values
    interfaces_off = type_list_offsets_by_values.get(spec.interfaces, 0)

    code_offsets: dict[str, int] = {}
    code_item_offsets: list[int] = []

    _align(data)
    constructor_code_off = data_off + len(data)
    code_offsets["<init>"] = constructor_code_off
    code_item_offsets.append(constructor_code_off)
    super_ctor_index = method_idx[(spec.superclass_descriptor, "<init>", constructor_proto)]
    if super_ctor_index > 0xFFFF:
        raise ValueError("constructor method index exceeds invoke-direct format 35c capacity")
    data.extend(struct.pack("<HHHHII", 1, 1, 1, 0, 0, 4))
    data.extend(struct.pack("<HHHH", 0x1070, super_ctor_index, 0x0000, 0x000E))

    if has_clinit:
        _align(data)
        clinit_code_off = data_off + len(data)
        code_offsets["<clinit>"] = clinit_code_off
        code_item_offsets.append(clinit_code_off)
        library_index = string_idx[spec.native_library or ""]
        load_index = method_idx[("Ljava/lang/System;", "loadLibrary", load_library_proto)]
        if library_index > 0xFFFF or load_index > 0xFFFF:
            raise ValueError("generated loadLibrary bridge exceeds 16-bit DEX instruction index")
        # const-string v0, library; invoke-static {v0}, System.loadLibrary; return-void.
        data.extend(struct.pack("<HHHHII", 1, 0, 1, 0, 0, 6))
        data.extend(struct.pack("<HHHHHH", 0x001A, library_index, 0x1071, load_index, 0x0000, 0x000E))

    for item in spec.forwarding_overrides:
        _align(data)
        code_off = data_off + len(data)
        code_offsets[item.name] = code_off
        code_item_offsets.append(code_off)
        native_index = method_idx[(spec.class_descriptor, item.native_target, item.proto)]
        register_count = 1 + len(item.proto.parameters)
        if not item.compact:
            # Range form (ADR-199): ins = this + parameters (J/D take two registers), below them
            # one or two result registers.  invoke-super/range when calling super (void only),
            # invoke-direct/range to the native, move-result*, return*.
            ins = 1 + sum(2 if parameter in {"J", "D"} else 1 for parameter in item.proto.parameters)
            result = item.proto.return_type
            width = 0 if result == "V" else 2 if result in {"J", "D"} else 1
            if ins + width > 0xFFFF or native_index > 0xFFFF:
                raise ValueError("forwarding override exceeds DEX range-invoke capacity")
            units = []
            if item.call_super:
                super_index = method_idx[(spec.superclass_descriptor, item.name, item.proto)]
                if super_index > 0xFFFF:
                    raise ValueError("forwarding override superclass method index exceeds 16-bit DEX capacity")
                units += [0x0075 | (ins << 8), super_index, width]   # invoke-super/range {v[width]..}
            units += [0x0076 | (ins << 8), native_index, width]       # invoke-direct/range {v[width]..}, native
            if result == "V":
                units.append(0x000E)                                     # return-void
            elif width == 2:
                units += [0x000B, 0x0010]                                # move-result-wide v0; return-wide v0
            elif result.startswith(("L", "[")):
                units += [0x000C, 0x0011]                                # move-result-object v0; return-object v0
            else:
                units += [0x000A, 0x000F]                                # move-result v0; return v0
            data.extend(struct.pack("<HHHHII", ins + width, ins, ins, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))
            continue
        if register_count > 5:
            raise ValueError("forwarding override exceeds DEX format 35c register capacity")
        if native_index > 0xFFFF:
            raise ValueError("forwarding override method index exceeds 16-bit DEX capacity")
        # Parameters are the only registers: v0=this, v1..=arguments.  Both
        # bridge forms cross into native XAX exactly once and allocate nothing.
        first_native = 0x0070 | (register_count << 12)
        register_word = sum(index << (index * 4) for index in range(register_count))
        if spec.native_library_load_override == item.name:
            library_index = string_idx[spec.native_library or ""]
            load_index = method_idx[("Ljava/lang/System;", "loadLibrary", load_library_proto)]
            if library_index > 0xFFFF or load_index > 0xFFFF:
                raise ValueError("deferred loadLibrary bridge exceeds 16-bit DEX instruction index")
            # v0 is a local library-name string. Incoming registers are shifted
            # to v1.. and preserve the exact instance/native callback arguments.
            incoming = tuple(range(1, register_count + 1))
            if register_count + 1 > 16:
                raise ValueError("deferred loadLibrary forwarding exceeds DEX register capacity")
            native_word = sum(reg << (position * 4) for position, reg in enumerate(incoming))
            first_deferred_native = 0x0070 | (register_count << 12)
            units = (
                0x001A, library_index,                 # const-string v0, library
                0x1071, load_index, 0x0000,           # invoke-static {v0}, System.loadLibrary
                first_deferred_native, native_index, native_word,
                0x000E,                               # return-void
            )
            data.extend(struct.pack("<HHHHII", register_count + 1, register_count, max(1, register_count), 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))
        elif hook_install is not None and item.name == "onPackageReady":
            if item.proto != DexProto("V", (libxposed_package_ready,)):
                raise ValueError("libxposed hook installation requires onPackageReady(PackageReadyParam)")
            get_loader = method_idx[(libxposed_package_ready, "getClassLoader", get_class_loader_proto)]
            load_class = method_idx[(class_loader_type, "loadClass", load_class_proto)]
            get_method = method_idx[(class_type, "getDeclaredMethod", get_declared_method_proto)]
            hook_method = method_idx[(libxposed_wrapper, "hook", hook_proto)]
            deoptimize_method = (
                method_idx[(libxposed_wrapper, "deoptimize", deoptimize_proto)]
                if hook_install.deoptimize_before_hook
                else None
            )
            set_mode = method_idx[(libxposed_hook_builder, "setExceptionMode", set_exception_mode_proto)]
            set_id_method = (
                method_idx[(libxposed_hook_builder, "setId", set_id_proto)]
                if hook_install.hook_id is not None else None
            )
            intercept_method = method_idx[(libxposed_hook_builder, "intercept", intercept_builder_proto)]
            hooker_ctor = method_idx[(hook_install.hooker_class_descriptor, "<init>", constructor_proto)]
            protective_field = field_idx[(libxposed_exception_mode, hook_install.exception_mode, libxposed_exception_mode)]
            retained_handle_field = (
                field_idx[(spec.class_descriptor, "xaxHookHandle", libxposed_hook_handle)]
                if hook_install.lifetime_policy == "retained-manual-unhook"
                else None
            )
            reload_loader_field = (
                field_idx[(spec.class_descriptor, "xaxReloadClassLoader", class_loader_type)]
                if hot_reload is not None else None
            )
            hooker_type = type_idx[hook_install.hooker_class_descriptor]
            class_name_string = string_idx[hook_install.target_class_binary_name]
            method_name_string = string_idx[hook_install.target_method_name]
            parameter_name_string = (
                string_idx[hook_install.parameter_type_binary_names[0]]
                if hook_install.parameter_type_binary_names
                else None
            )
            class_array_type_index = type_idx[class_array_type]
            bounded_indices = (
                get_loader, load_class, get_method, hook_method, set_mode, intercept_method,
                hooker_ctor, protective_field, hooker_type, class_name_string, method_name_string,
                class_array_type_index,
                native_index,
            )
            if set_id_method is not None:
                bounded_indices += (set_id_method, string_idx[hook_install.hook_id or ""],)
            if deoptimize_method is not None:
                bounded_indices += (deoptimize_method,)
            if parameter_name_string is not None:
                bounded_indices += (parameter_name_string,)
            if retained_handle_field is not None:
                bounded_indices += (retained_handle_field,)
            if reload_loader_field is not None:
                bounded_indices += (reload_loader_field,)
            if any(value > 0xFFFF for value in bounded_indices):
                raise ValueError("libxposed hook installation exceeds 16-bit DEX instruction index")

            def install_invoke(opcode: int, method: int, registers: tuple[int, ...]) -> tuple[int, int, int]:
                if len(registers) > 5 or any(not 0 <= reg <= 15 for reg in registers):
                    raise ValueError("libxposed hook installation exceeds DEX 35c register capacity")
                first = opcode | (len(registers) << 12)
                word = sum(reg << (position * 4) for position, reg in enumerate(registers))
                return first, method, word

            units: list[int] = []
            if parameter_name_string is None:
                # Locals: v0 loader/method-name, v1 class, v2 Method,
                # v3 HookBuilder, v4 Hooker, v5 ExceptionMode, v6 HookHandle.
                # Incoming v7=this, v8=PackageReadyParam.
                units.extend(install_invoke(0x72, get_loader, (8,)))
                units.append(0x000C)  # move-result-object v0
                if reload_loader_field is not None:
                    units.extend((0x705B, reload_loader_field))  # iput-object v0, v7(this), xaxReloadClassLoader
                units.extend((0x011A, class_name_string))
                units.extend(install_invoke(0x6E, load_class, (0, 1)))
                units.append(0x010C)  # move-result-object v1
                units.extend((0x001A, method_name_string))
                units.append(0x0312)  # const/4 v3, #0 => null Class[] for zero-arg target
                units.extend(install_invoke(0x6E, get_method, (1, 0, 3)))
                units.append(0x020C)  # move-result-object v2
                if deoptimize_method is not None:
                    # Explicit best-effort deoptimization. The API returns a
                    # boolean; this bounded semantic policy deliberately ignores
                    # it and proceeds to hook installation.
                    units.extend(install_invoke(0x6E, deoptimize_method, (7, 2)))
                units.extend(install_invoke(0x6E, hook_method, (7, 2)))
                units.append(0x030C)  # move-result-object v3
                units.extend((0x0562, protective_field))
                units.extend(install_invoke(0x72, set_mode, (3, 5)))
                units.append(0x030C)
                if set_id_method is not None:
                    units.extend((0x061A, string_idx[hook_install.hook_id or ""]))
                    units.extend(install_invoke(0x72, set_id_method, (3, 6)))
                    units.append(0x030C)
                units.extend((0x0422, hooker_type))
                units.extend(install_invoke(0x70, hooker_ctor, (4,)))
                units.extend(install_invoke(0x72, intercept_method, (3, 4)))
                units.append(0x060C)
                if retained_handle_field is not None:
                    units.extend((0x765B, retained_handle_field))  # iput-object v6, v7(this), xaxHookHandle
                units.extend(install_invoke(0x70, native_index, (7, 8)))
                units.append(0x000E)
                registers_size = 9
            else:
                # One-String-parameter bounded profile. Locals v0..v8; incoming
                # v9=this, v10=PackageReadyParam. The Class[1] allocation occurs
                # once at install time and never appears in the interceptor.
                units.extend(install_invoke(0x72, get_loader, (10,)))
                units.append(0x000C)  # v0 loader
                if reload_loader_field is not None:
                    units.extend((0x905B, reload_loader_field))  # iput-object v0, v9(this), xaxReloadClassLoader
                units.extend((0x011A, class_name_string))
                units.extend(install_invoke(0x6E, load_class, (0, 1)))
                units.append(0x010C)  # v1 target Class
                units.extend((0x071A, parameter_name_string))
                units.extend(install_invoke(0x6E, load_class, (0, 7)))
                units.append(0x070C)  # v7 parameter Class
                units.append(0x1812)  # const/4 v8, #1
                units.extend((0x8823, class_array_type_index))  # new-array v8, v8, Class[]
                units.append(0x0612)  # const/4 v6, #0
                units.extend((0x074D, 0x0608))  # aput-object v7, v8, v6
                units.extend((0x001A, method_name_string))
                units.extend(install_invoke(0x6E, get_method, (1, 0, 8)))
                units.append(0x020C)
                if deoptimize_method is not None:
                    units.extend(install_invoke(0x6E, deoptimize_method, (9, 2)))
                units.extend(install_invoke(0x6E, hook_method, (9, 2)))
                units.append(0x030C)
                units.extend((0x0562, protective_field))
                units.extend(install_invoke(0x72, set_mode, (3, 5)))
                units.append(0x030C)
                if set_id_method is not None:
                    units.extend((0x061A, string_idx[hook_install.hook_id or ""]))
                    units.extend(install_invoke(0x72, set_id_method, (3, 6)))
                    units.append(0x030C)
                units.extend((0x0422, hooker_type))
                units.extend(install_invoke(0x70, hooker_ctor, (4,)))
                units.extend(install_invoke(0x72, intercept_method, (3, 4)))
                units.append(0x060C)
                if retained_handle_field is not None:
                    units.extend((0x965B, retained_handle_field))  # iput-object v6, v9(this), xaxHookHandle
                units.extend(install_invoke(0x70, native_index, (9, 10)))
                units.append(0x000E)
                registers_size = 11
            data.extend(struct.pack("<HHHHII", registers_size, 2, 3, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))
        elif item.call_super and activity_ui is not None and item.name == "onCreate":
            # Locals: v0=Button, v1=String, v2=listener. Incoming registers are
            # v3=this and v4=Bundle because DEX places parameters at the high end.
            if item.proto != DexProto("V", ("Landroid/os/Bundle;",)):
                raise ValueError("managed Activity UI setup requires onCreate(Bundle)")
            super_index = method_idx[(spec.superclass_descriptor, item.name, item.proto)]
            button_ctor = method_idx[("Landroid/widget/Button;", "<init>", button_ctor_proto)]
            set_text = method_idx[("Landroid/widget/TextView;", "setText", activity_set_text_proto)]
            listener_ctor = method_idx[(activity_ui.listener_class_descriptor, "<init>", constructor_proto)]
            set_listener = method_idx[("Landroid/view/View;", "setOnClickListener", set_listener_proto)]
            set_content = method_idx[("Landroid/app/Activity;", "setContentView", set_content_view_proto)]
            button_type = type_idx["Landroid/widget/Button;"]
            listener_type = type_idx[activity_ui.listener_class_descriptor]
            text_index = string_idx[activity_ui.button_text] if activity_ui.button_text is not None else None
            text_method = (
                method_idx[(
                    spec.class_descriptor,
                    activity_ui.button_text_method_name,
                    DexProto(
                        "Ljava/lang/String;",
                        ("Ljava/lang/String;",) if activity_ui.button_text_method_argument is not None else (),
                    ),
                )]
                if activity_ui.button_text_method_name is not None
                else None
            )
            text_method_argument_index = (
                string_idx[activity_ui.button_text_method_argument]
                if activity_ui.button_text_method_argument is not None
                else None
            )
            bounded_indices = (
                super_index, button_ctor, set_text, listener_ctor, set_listener, set_content,
                native_index, button_type, listener_type,
                *(tuple((text_method,)) if text_method is not None else ()),
                *(tuple((text_method_argument_index,)) if text_method_argument_index is not None else ()),
            )
            if any(value > 0xFFFF for value in bounded_indices) or (text_index is not None and text_index > 0xFFFF):
                raise ValueError("managed Activity UI setup exceeds 16-bit DEX instruction index")

            def invoke(opcode: int, method: int, registers: tuple[int, ...]) -> tuple[int, int, int]:
                if len(registers) > 5 or any(not 0 <= reg <= 15 for reg in registers):
                    raise ValueError("managed Activity UI invoke exceeds DEX 35c register capacity")
                first = opcode | (len(registers) << 12)
                word = sum(reg << (position * 4) for position, reg in enumerate(registers))
                return first, method, word

            units: list[int] = []
            units.extend(invoke(0x6F, super_index, (3, 4)))
            units.extend((0x0022, button_type))  # new-instance v0, Button
            units.extend(invoke(0x70, button_ctor, (0, 3)))
            if text_index is not None:
                units.extend((0x011A, text_index))  # const-string v1, initial text
            elif text_method is not None:
                if text_method_argument_index is None:
                    units.extend(invoke(0x6E, text_method, (3,)))
                else:
                    units.extend((0x011A, text_method_argument_index))  # const-string v1, controlled argument
                    units.extend(invoke(0x6E, text_method, (3, 1)))
                units.append(0x010C)  # move-result-object v1
            else:
                resource_id = activity_ui.button_text_resource_id or 0
                units.extend((0x0114, resource_id & 0xFFFF, (resource_id >> 16) & 0xFFFF))  # const v1, resource ID
            units.extend(invoke(0x6E, set_text, (0, 1)))
            units.extend((0x0222, listener_type))  # new-instance v2, generated listener
            units.extend(invoke(0x70, listener_ctor, (2,)))
            units.extend(invoke(0x6E, set_listener, (0, 2)))
            units.extend(invoke(0x6E, set_content, (3, 0)))
            units.extend(invoke(0x70, native_index, (3, 4)))
            units.append(0x000E)
            data.extend(struct.pack("<HHHHII", 5, 2, 2, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))
        elif click_text is not None and item.name == "onClick":
            # Locals: v0=String. Incoming registers are v1=this, v2=View.
            # Narrow the clicked View to TextView/Button, update visible text, then
            # cross into native XAX exactly once. No allocation occurs here.
            text_type = type_idx["Landroid/widget/TextView;"]
            text_index = string_idx[click_text.text] if click_text.text is not None else None
            set_text = method_idx[("Landroid/widget/TextView;", "setText", click_set_text_proto)]
            if any(value > 0xFFFF for value in (text_type, set_text, native_index)) or (text_index is not None and text_index > 0xFFFF):
                raise ValueError("managed click text mutation exceeds 16-bit DEX instruction index")
            units = [0x021F, text_type]  # check-cast v2, TextView
            if text_index is not None:
                units.extend((0x001A, text_index))  # const-string v0, click text
            else:
                resource_id = click_text.text_resource_id or 0
                units.extend((0x0014, resource_id & 0xFFFF, (resource_id >> 16) & 0xFFFF))  # const v0, resource ID
            units.extend((
                0x206E, set_text, 0x0002,             # invoke-virtual {v2,v0}, setText
                0x2070, native_index, 0x0021,         # invoke-direct {v1,v2}, native callback
                0x000E,                               # return-void
            ))
            data.extend(struct.pack("<HHHHII", 3, 2, 2, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))
        elif item.call_super:
            super_index = method_idx[(spec.superclass_descriptor, item.name, item.proto)]
            if super_index > 0xFFFF:
                raise ValueError("forwarding override superclass method index exceeds 16-bit DEX capacity")
            first_super = 0x006F | (register_count << 12)
            data.extend(struct.pack("<HHHHII", register_count, register_count, register_count, 0, 0, 7))
            data.extend(struct.pack("<7H", first_super, super_index, register_word, first_native, native_index, register_word, 0x000E))
        else:
            data.extend(struct.pack("<HHHHII", register_count, register_count, register_count, 0, 0, 4))
            data.extend(struct.pack("<4H", first_native, native_index, register_word, 0x000E))

    if hook_intercept is not None:
        _align(data)
        code_off = data_off + len(data)
        code_offsets["intercept"] = code_off
        code_item_offsets.append(code_off)
        proceed_index = method_idx[(libxposed_chain, "proceed", hook_proceed_proto)]
        proceed_args_index = (
            method_idx[(libxposed_chain, "proceed", hook_proceed_args_proto)]
            if hook_intercept.argument_replacement_string is not None
            else None
        )
        get_arg_index = (
            method_idx[(libxposed_chain, "getArg", hook_get_arg_proto)]
            if hook_intercept.inspected_argument_index is not None
            else None
        )
        if (
            proceed_index > 0xFFFF
            or (get_arg_index is not None and get_arg_index > 0xFFFF)
            or (proceed_args_index is not None and proceed_args_index > 0xFFFF)
        ):
            raise ValueError("libxposed hook interceptor method index exceeds 16-bit DEX capacity")
        if hook_intercept.argument_replacement_string is not None:
            replacement_index = string_idx[hook_intercept.argument_replacement_string]
            result_replacement_index = (
                string_idx[hook_intercept.replacement_string]
                if hook_intercept.replacement_string is not None
                else None
            )
            object_array_type = type_idx["[Ljava/lang/Object;"]
            if (
                replacement_index > 0xFFFF
                or (result_replacement_index is not None and result_replacement_index > 0xFFFF)
                or object_array_type > 0xFFFF
                or proceed_args_index is None
                or get_arg_index is None
            ):
                raise ValueError("libxposed argument replacement exceeds bounded DEX index capacity")
            # v0=index, v1=observed original arg, v2=Object[1], v3=replacement,
            # v4=result, incoming v5=this, v6=Chain. The Object[] allocation is
            # explicit and attributable to this hook invocation.
            units = [
                0x0012,                         # const/4 v0, #0
                0x2072, get_arg_index, 0x0006, # Chain.getArg(0)
                0x010C,                         # move-result-object v1
                0x1212,                         # const/4 v2, #1
                0x2223, object_array_type,      # new-array v2, v2, Object[]
                0x031A, replacement_index,      # const-string v3, replacement
                0x0012,                         # const/4 v0, #0
                0x034D, 0x0002,                 # aput-object v3, v2, v0
                0x2072, proceed_args_index, 0x0026, # Chain.proceed(v2)
                0x040C,                         # move-result-object v4
            ]
            if result_replacement_index is None:
                units.append(0x0411)             # return-object v4
            else:
                # Preserve the original result in v4, then make the explicit
                # post-proceed constant result policy win. v3 is dead after the
                # argument array store and can be reused without allocation.
                units.extend((0x031A, result_replacement_index, 0x0311))
            units = tuple(units)
            data.extend(struct.pack("<HHHHII", 7, 2, 2, 0, 0, len(units)))
        elif get_arg_index is None and hook_intercept.replacement_string is not None:
            # v0=original result, v1=replacement, v2=this, v3=Chain.  The
            # original target executes exactly once and its Object result is
            # captured before the explicit constant String replacement wins.
            replacement_index = string_idx[hook_intercept.replacement_string]
            if replacement_index > 0xFFFF:
                raise ValueError("libxposed replacement String exceeds const-string index capacity")
            units = (
                0x1072, proceed_index, 0x0003,
                0x000C,
                0x011A, replacement_index,
                0x0111,
            )
            data.extend(struct.pack("<HHHHII", 4, 2, 1, 0, 0, len(units)))
        elif get_arg_index is None:
            # v0=result, v1=this, v2=Chain.  Pure pass-through: exactly one
            # proceed, no argument access, lookup, reflection, or allocation.
            units = (
                0x1072, proceed_index, 0x0002,
                0x000C,
                0x0011,
            )
            data.extend(struct.pack("<HHHHII", 3, 2, 1, 0, 0, len(units)))
        else:
            # v0 = inspected argument (deliberately discarded after the semantic
            # read), v1 = result, v2 = this, v3 = Chain.  This shape contains no
            # allocation and exactly one Chain.proceed() invocation.
            const_index = 0x0012 | (hook_intercept.inspected_argument_index << 12)
            units = (
                const_index,
                0x2072, get_arg_index, 0x0003,  # invoke-interface {v3,v0}, Chain.getArg
                0x000C,                         # move-result-object v0
                0x1072, proceed_index, 0x0003,  # invoke-interface {v3}, Chain.proceed
                0x010C,                         # move-result-object v1
                0x0111,                         # return-object v1
            )
            data.extend(struct.pack("<HHHHII", 4, 2, 2, 0, 0, len(units)))
        data.extend(struct.pack(f"<{len(units)}H", *units))

    for item in spec.constant_string_methods:
        _align(data)
        code_off = data_off + len(data)
        code_offsets[item.name] = code_off
        code_item_offsets.append(code_off)
        string_index = string_idx[item.value]
        if string_index > 0xFFFF:
            raise ValueError("constant string method exceeds const-string index capacity")
        # v0 is the local result and v1 is the incoming instance receiver.
        units = (0x001A, string_index, 0x0011)
        data.extend(struct.pack("<HHHHII", 2, 1, 0, 0, 0, len(units)))
        data.extend(struct.pack("<3H", *units))

    for item in spec.echo_string_methods:
        _align(data)
        code_off = data_off + len(data)
        code_offsets[item.name] = code_off
        code_item_offsets.append(code_off)
        # Incoming registers: v0=this, v1=String argument. Return the argument.
        units = (0x0111,)
        data.extend(struct.pack("<HHHHII", 2, 2, 0, 0, 0, len(units)))
        data.extend(struct.pack("<H", *units))

    if module_services is not None:
        for service in module_services.services:
            generated_name, framework_name, proto = module_service_methods[service]
            _align(data)
            code_off = data_off + len(data)
            code_offsets[generated_name] = code_off
            code_item_offsets.append(code_off)
            framework_method = method_idx[(libxposed_wrapper, framework_name, proto)]
            if framework_method > 0xFFFF:
                raise ValueError("libxposed module-service method exceeds DEX invoke index capacity")
            if len(proto.parameters) == 0:
                # v0=result, incoming v1=this.
                units = (
                    0x106E, framework_method, 0x0001,
                    0x000C,
                    0x0011,
                )
                registers_size, ins_size, outs_size = 2, 1, 1
            elif proto.parameters == (string_type,):
                # v0=result, incoming v1=this, v2=String argument.
                units = (
                    0x206E, framework_method, 0x0021,
                    0x000C,
                    0x0011,
                )
                registers_size, ins_size, outs_size = 3, 2, 2
            else:
                raise AssertionError("unexpected bounded libxposed module-service prototype")
            data.extend(struct.pack("<HHHHII", registers_size, ins_size, outs_size, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))

    if remote_preferences is not None:
        # Nullable acquisition helper.  It checks framework properties directly:
        # (getFrameworkProperties() & PROP_CAP_REMOTE) != 0, where PROP_CAP_REMOTE
        # is API bit 1.  Unsupported frameworks return null without attempting the
        # remote call; supported-framework failures still propagate normally.
        _align(data)
        code_off = data_off + len(data)
        code_offsets["xaxRemotePreferencesIfSupported"] = code_off
        code_item_offsets.append(code_off)
        properties_method = method_idx[(libxposed_wrapper, "getFrameworkProperties", framework_properties_proto)]
        preferences_method = method_idx[(libxposed_wrapper, "getRemotePreferences", remote_preferences_proto)]
        if properties_method > 0xFFFF or preferences_method > 0xFFFF:
            raise ValueError("libxposed remote-preferences capability method exceeds DEX invoke index capacity")
        # v0/v1 = long framework properties local; incoming v2=this, v3=group.
        # long-to-int is safe after masking interest to the low capability bits;
        # and-int/lit8 isolates PROP_CAP_REMOTE (1 << 1).
        units = (
            0x106E, properties_method, 0x0002,  # invoke-virtual {v2}, getFrameworkProperties()J
            0x000B,                             # move-result-wide v0
            0x0084,                             # long-to-int v0, v0
            0x00DD, 0x0200,                     # and-int/lit8 v0, v0, #2
            0x0038, 0x0007,                     # if-eqz v0, +7 -> nullable fallback
            0x206E, preferences_method, 0x0032, # invoke-virtual {v2,v3}, getRemotePreferences
            0x000C,                             # move-result-object v0
            0x0011,                             # return-object v0
            0x0012,                             # const/4 v0, #0
            0x0011,                             # return-object v0
        )
        data.extend(struct.pack("<HHHHII", 4, 2, 2, 0, 0, len(units)))
        data.extend(struct.pack(f"<{len(units)}H", *units))

        for read in remote_preferences.reads:
            generated_name, interface_name, generated_proto, interface_proto = remote_preference_methods[read]
            _align(data)
            code_off = data_off + len(data)
            code_offsets[generated_name] = code_off
            code_item_offsets.append(code_off)
            interface_method = method_idx[(shared_preferences_type, interface_name, interface_proto)]
            if interface_method > 0xFFFF:
                raise ValueError("SharedPreferences read method exceeds DEX invoke index capacity")
            if read in ("boolean", "int", "float"):
                # v0=result; incoming v1=this, v2=prefs, v3=key, v4=default.
                units = (
                    0x3072, interface_method, 0x0432,
                    0x000A,
                    0x000F,
                )
                registers_size, ins_size, outs_size = 5, 4, 3
            elif read == "long":
                # v0/v1=result; incoming v2=this, v3=prefs, v4=key, v5/v6=default.
                units = (
                    0x4072, interface_method, 0x6543,
                    0x000B,
                    0x0010,
                )
                registers_size, ins_size, outs_size = 7, 5, 4
            elif read == "string":
                # v0=result; incoming v1=this, v2=prefs, v3=key, v4=default.
                units = (
                    0x3072, interface_method, 0x0432,
                    0x000C,
                    0x0011,
                )
                registers_size, ins_size, outs_size = 5, 4, 3
            elif read == "contains":
                # v0=result; incoming v1=this, v2=prefs, v3=key.
                units = (
                    0x2072, interface_method, 0x0032,
                    0x000A,
                    0x000F,
                )
                registers_size, ins_size, outs_size = 4, 3, 2
            else:
                raise AssertionError("unexpected bounded SharedPreferences read")
            data.extend(struct.pack("<HHHHII", registers_size, ins_size, outs_size, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))

    if remote_files is not None:
        properties_method = method_idx[(libxposed_wrapper, "getFrameworkProperties", framework_properties_proto)]
        if properties_method > 0xFFFF:
            raise ValueError("libxposed remote-file capability method exceeds DEX invoke index capacity")
        for operation in remote_files.operations:
            if operation == "list":
                generated_name = "xaxListRemoteFilesIfSupported"
                remote_method = method_idx[(libxposed_wrapper, "listRemoteFiles", list_remote_files_proto)]
                incoming_this = 2
                invoke_word = 0x0002
                registers_size, ins_size, outs_size = 3, 1, 1
            elif operation == "open":
                generated_name = "xaxOpenRemoteFileIfSupported"
                remote_method = method_idx[(libxposed_wrapper, "openRemoteFile", open_remote_file_proto)]
                incoming_this = 2
                invoke_word = 0x0032
                registers_size, ins_size, outs_size = 4, 2, 2
            else:
                raise AssertionError("unexpected bounded remote-file operation")
            if remote_method > 0xFFFF:
                raise ValueError("libxposed remote-file method exceeds DEX invoke index capacity")
            _align(data)
            code_off = data_off + len(data)
            code_offsets[generated_name] = code_off
            code_item_offsets.append(code_off)
            invoke_first = 0x106E if operation == "list" else 0x206E
            units = (
                0x106E, properties_method, incoming_this,  # invoke-virtual {this}, getFrameworkProperties()J
                0x000B,                                   # move-result-wide v0
                0x0084,                                   # long-to-int v0, v0
                0x00DD, 0x0200,                           # and-int/lit8 v0, v0, #2
                0x0038, 0x0007,                           # if-eqz v0, +7 -> nullable fallback
                invoke_first, remote_method, invoke_word,  # selected remote operation
                0x000C,                                   # move-result-object v0
                0x0011,                                   # return-object v0
                0x0012,                                   # const/4 v0, #0
                0x0011,                                   # return-object v0
            )
            data.extend(struct.pack("<HHHHII", registers_size, ins_size, outs_size, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))

    if hot_reload is not None:
        # Old-generation callback: preserve only the target/app ClassLoader
        # captured from PackageReadyParam. It is host-owned rather than a
        # module-generation object, so it can cross the API-102 saved-state
        # boundary without retaining the old module ClassLoader. If package
        # readiness never occurred, explicitly reject reload.
        _align(data)
        code_off = data_off + len(data)
        code_offsets["onHotReloading"] = code_off
        code_item_offsets.append(code_off)
        reload_loader_field = field_idx[(spec.class_descriptor, "xaxReloadClassLoader", class_loader_type)]
        set_saved_state_method = method_idx[(libxposed_hot_reloading, "setSavedInstanceState", set_saved_instance_state_proto)]
        if reload_loader_field > 0xFFFF or set_saved_state_method > 0xFFFF:
            raise ValueError("libxposed hot-reload saved state exceeds 16-bit DEX index capacity")
        # v0=stored target ClassLoader. Incoming v1=this, v2=HotReloadingParam.
        units = (
            0x1054, reload_loader_field,            # iget-object v0, v1(this), xaxReloadClassLoader
            0x0038, 0x0007,                        # if-eqz v0, reject reload
            0x2072, set_saved_state_method, 0x0002, # invoke-interface {v2,v0}, setSavedInstanceState
            0x1012,                                # const/4 v0, #1
            0x000F,                                # return v0
            0x0012,                                # const/4 v0, #0
            0x000F,                                # return v0
        )
        data.extend(struct.pack("<HHHHII", 3, 2, 2, 0, 0, len(units)))
        data.extend(struct.pack(f"<{len(units)}H", *units))

        # New-generation callback: restore the host-owned target ClassLoader,
        # then the build closure proves this module owns exactly one retained
        # generated hook. Recover that sole old handle and
        # use API-102 HookHandle.replaceHook(new Hooker()) so replacement is
        # atomic rather than unhook+install. Framework/runtime failures are not
        # swallowed by the generated bridge.
        _align(data)
        code_off = data_off + len(data)
        code_offsets["onHotReloaded"] = code_off
        code_item_offsets.append(code_off)
        get_saved_state_method = method_idx[(libxposed_hot_reloaded, "getSavedInstanceState", get_saved_instance_state_proto)]
        old_handles_method = method_idx[(libxposed_hot_reloaded, "getOldHookHandles", old_hook_handles_proto)]
        list_get_method = method_idx[(list_type, "get", list_get_proto)]
        list_is_empty_method = method_idx[(list_type, "isEmpty", list_is_empty_proto)]
        get_id_method = method_idx[(libxposed_hook_handle, "getId", get_hook_id_proto)]
        string_equals_method = method_idx[(string_type, "equals", string_equals_proto)]
        hooker_ctor = method_idx[(hot_reload.hooker_class_descriptor, "<init>", constructor_proto)]
        replace_method = method_idx[(libxposed_hook_handle, "replaceHook", replace_hook_proto)]
        hook_handle_type = type_idx[libxposed_hook_handle]
        hooker_type = type_idx[hot_reload.hooker_class_descriptor]
        reload_loader_type = type_idx[class_loader_type]
        hook_id_string = string_idx[hot_reload.hook_id]
        retained_handle_field = field_idx[(spec.class_descriptor, "xaxHookHandle", libxposed_hook_handle)]
        reload_loader_field = field_idx[(spec.class_descriptor, "xaxReloadClassLoader", class_loader_type)]
        bounded_indices = (
            get_saved_state_method, old_handles_method, list_get_method, list_is_empty_method, get_id_method, string_equals_method,
            hooker_ctor, replace_method, hook_handle_type, hooker_type, reload_loader_type, hook_id_string,
            retained_handle_field, reload_loader_field,
        )
        if any(value > 0xFFFF for value in bounded_indices):
            raise ValueError("libxposed hot-reload replacement exceeds 16-bit DEX index capacity")
        # v0=saved state/old handle List, v1=old HookHandle, v2=boolean/current ID,
        # v3=expected ID/new Hooker. Incoming v4=this, v5=HotReloadedParam.
        # Missing saved state, empty old handles, or an ID mismatch is an
        # explicit no-op; API/framework exceptions still propagate.
        units = (
            0x1072, get_saved_state_method, 0x0005, # invoke-interface {v5}, getSavedInstanceState
            0x000C,                                 # move-result-object v0
            0x0038, 0x002E,                         # if-eqz v0, return
            0x001F, reload_loader_type,              # check-cast v0, ClassLoader
            0x405B, reload_loader_field,             # iput-object v0, v4(this), xaxReloadClassLoader
            0x1072, old_handles_method, 0x0005,      # invoke-interface {v5}, getOldHookHandles
            0x000C,                                  # move-result-object v0 (List)
            0x1072, list_is_empty_method, 0x0000, # invoke-interface {v0}, List.isEmpty
            0x020A,                               # move-result v2
            0x0239, 0x0020,                       # if-nez v2, return
            0x0212,                               # const/4 v2, #0
            0x2072, list_get_method, 0x0020,      # invoke-interface {v0,v2}, List.get(0)
            0x010C,                               # move-result-object v1
            0x011F, hook_handle_type,             # check-cast v1, HookHandle
            0x1072, get_id_method, 0x0001,        # invoke-interface {v1}, HookHandle.getId
            0x020C,                               # move-result-object v2
            0x031A, hook_id_string,               # const-string v3, expected ID
            0x206E, string_equals_method, 0x0023, # invoke-virtual {v3,v2}, String.equals
            0x020A,                               # move-result v2
            0x0238, 0x000D,                       # if-eqz v2, return
            0x0322, hooker_type,                  # new-instance v3, generated Hooker
            0x1070, hooker_ctor, 0x0003,          # invoke-direct {v3}, <init>
            0x2072, replace_method, 0x0031,       # invoke-interface {v1,v3}, replaceHook
            0x030C,                               # move-result-object v3
            0x435B, retained_handle_field,        # iput-object v3, v4(this), xaxHookHandle
            0x000E,                               # return-void
        )
        data.extend(struct.pack("<HHHHII", 6, 2, 2, 0, 0, len(units)))
        data.extend(struct.pack(f"<{len(units)}H", *units))

    for item in spec.null_return_overrides:
        _align(data)
        code_off = data_off + len(data)
        code_offsets[item.name] = code_off
        code_item_offsets.append(code_off)
        ins_count = 1 + len(item.proto.parameters)
        register_count = ins_count + 1  # v0 local null, incoming parameters occupy high registers.
        if register_count > 0xFFFF:
            raise ValueError("null-return override register count exceeds DEX code_item capacity")
        # const/4 v0, #0; return-object v0.
        data.extend(struct.pack("<HHHHII", register_count, ins_count, 0, 0, 0, 2))
        data.extend(struct.pack("<2H", 0x0012, 0x0011))

    if hook_install is not None and hook_install.lifetime_policy == "retained-manual-unhook":
        _align(data)
        code_off = data_off + len(data)
        code_offsets["xaxUnhook"] = code_off
        code_item_offsets.append(code_off)
        retained_handle_field = field_idx[(spec.class_descriptor, "xaxHookHandle", libxposed_hook_handle)]
        unhook_method = method_idx[(libxposed_hook_handle, "unhook", constructor_proto)]
        if retained_handle_field > 0xFFFF or unhook_method > 0xFFFF:
            raise ValueError("libxposed retained HookHandle unhook exceeds 16-bit DEX index capacity")
        # v0=retained HookHandle local, incoming v1=this.  Clearing the field
        # makes the generated operation idempotent before relying on the
        # framework's own idempotent HookHandle.unhook contract.
        units = (
            0x1054, retained_handle_field,       # iget-object v0, v1, xaxHookHandle
            0x0038, 0x0008,                      # if-eqz v0, +8 -> return-void
            0x1072, unhook_method, 0x0000,       # invoke-interface {v0}, HookHandle.unhook
            0x0012,                              # const/4 v0, #0
            0x105B, retained_handle_field,       # iput-object v0, v1, xaxHookHandle
            0x000E,                              # return-void
        )
        data.extend(struct.pack("<HHHHII", 2, 1, 1, 0, 0, len(units)))
        data.extend(struct.pack(f"<{len(units)}H", *units))

    for item in spec.assembled_methods:
        _align(data)
        code_off = data_off + len(data)
        code_offsets[item.name] = code_off
        code_item_offsets.append(code_off)
        units = _assemble(item, string_idx, type_idx, method_idx)
        data.extend(struct.pack("<HHHHII", item.registers_size, item.ins_size, item.outs_size, 0, 0, len(units)))
        data.extend(struct.pack(f"<{len(units)}H", *units))

    class_data_off = data_off + len(data)
    direct_methods: list[tuple[str, DexProto, int, int]] = [
        ("<init>", constructor_proto, ACC_PUBLIC | ACC_CONSTRUCTOR, code_offsets["<init>"])
    ]
    if has_clinit:
        direct_methods.append(("<clinit>", constructor_proto, ACC_STATIC | ACC_CONSTRUCTOR, code_offsets["<clinit>"]))
    virtual_methods: list[tuple[str, DexProto, int, int]] = []
    for item in spec.native_methods:
        record = (item.name, item.proto, item.access_flags, 0)
        (direct_methods if item.access_flags & ACC_PRIVATE else virtual_methods).append(record)
    for item in spec.forwarding_overrides:
        virtual_methods.append((item.name, item.proto, item.access_flags, code_offsets[item.name]))
    for item in spec.null_return_overrides:
        virtual_methods.append((item.name, item.proto, item.access_flags, code_offsets[item.name]))
    for item in spec.constant_string_methods:
        virtual_methods.append((item.name, item.proto, item.access_flags, code_offsets[item.name]))
    for item in spec.echo_string_methods:
        virtual_methods.append((item.name, item.proto, item.access_flags, code_offsets[item.name]))
    for item in spec.assembled_methods:
        direct = item.access_flags & (ACC_PRIVATE | ACC_STATIC | ACC_CONSTRUCTOR)
        (direct_methods if direct else virtual_methods).append((item.name, item.proto, item.access_flags, code_offsets[item.name]))
    if module_services is not None:
        for service in module_services.services:
            generated_name, _, proto = module_service_methods[service]
            virtual_methods.append((generated_name, proto, ACC_PUBLIC, code_offsets[generated_name]))
    if remote_preferences is not None:
        virtual_methods.append((
            "xaxRemotePreferencesIfSupported",
            remote_preferences_proto,
            ACC_PUBLIC,
            code_offsets["xaxRemotePreferencesIfSupported"],
        ))
        for read in remote_preferences.reads:
            generated_name, _, generated_proto, _ = remote_preference_methods[read]
            virtual_methods.append((generated_name, generated_proto, ACC_PUBLIC, code_offsets[generated_name]))
    if remote_files is not None:
        if "list" in remote_files.operations:
            virtual_methods.append(("xaxListRemoteFilesIfSupported", list_remote_files_proto, ACC_PUBLIC, code_offsets["xaxListRemoteFilesIfSupported"]))
        if "open" in remote_files.operations:
            virtual_methods.append(("xaxOpenRemoteFileIfSupported", open_remote_file_proto, ACC_PUBLIC, code_offsets["xaxOpenRemoteFileIfSupported"]))
    if hot_reload is not None:
        virtual_methods.append(("onHotReloading", hot_reloading_proto, ACC_PUBLIC, code_offsets["onHotReloading"]))
        virtual_methods.append(("onHotReloaded", hot_reloaded_proto, ACC_PUBLIC, code_offsets["onHotReloaded"]))
    if hook_intercept is not None:
        virtual_methods.append(("intercept", hook_intercept_proto, ACC_PUBLIC, code_offsets["intercept"]))
    if hook_install is not None and hook_install.lifetime_policy == "retained-manual-unhook":
        virtual_methods.append(("xaxUnhook", constructor_proto, ACC_PUBLIC, code_offsets["xaxUnhook"]))
    direct_methods.sort(key=lambda item: method_idx[(spec.class_descriptor, item[0], item[1])])
    virtual_methods.sort(key=lambda item: method_idx[(spec.class_descriptor, item[0], item[1])])

    instance_fields: list[tuple[int, int]] = []
    if hook_install is not None and hook_install.lifetime_policy == "retained-manual-unhook":
        instance_fields.append((field_idx[(spec.class_descriptor, "xaxHookHandle", libxposed_hook_handle)], ACC_PRIVATE))
    if hot_reload is not None:
        instance_fields.append((field_idx[(spec.class_descriptor, "xaxReloadClassLoader", class_loader_type)], ACC_PRIVATE))
    instance_fields.sort(key=lambda item: item[0])

    class_data = bytearray()
    class_data.extend(_uleb(0) + _uleb(len(instance_fields)) + _uleb(len(direct_methods)) + _uleb(len(virtual_methods)))
    previous = 0
    for position, (index, flags) in enumerate(instance_fields):
        class_data.extend(_uleb(index if position == 0 else index - previous))
        class_data.extend(_uleb(flags))
        previous = index
    previous = 0
    for position, (name, proto, flags, code_off) in enumerate(direct_methods):
        index = method_idx[(spec.class_descriptor, name, proto)]
        class_data.extend(_uleb(index if position == 0 else index - previous))
        class_data.extend(_uleb(flags))
        class_data.extend(_uleb(code_off))
        previous = index
    previous = 0
    for position, (name, proto, flags, code_off) in enumerate(virtual_methods):
        index = method_idx[(spec.class_descriptor, name, proto)]
        class_data.extend(_uleb(index if position == 0 else index - previous))
        class_data.extend(_uleb(flags))
        class_data.extend(_uleb(code_off))
        previous = index
    data.extend(class_data)

    string_offsets: list[int] = []
    string_data_start = data_off + len(data)
    for value in strings_ordered:
        string_offsets.append(data_off + len(data))
        data.extend(_uleb(len(_utf16_units(value))) + _mutf8(value) + b"\x00")

    _align(data)
    map_off = data_off + len(data)
    map_items: list[tuple[int, int, int]] = [
        (TYPE_HEADER_ITEM, 1, 0),
        (TYPE_STRING_ID_ITEM, len(strings_ordered), string_ids_off),
        (TYPE_TYPE_ID_ITEM, len(types_ordered), type_ids_off),
        (TYPE_PROTO_ID_ITEM, len(protos_ordered), proto_ids_off),
        (TYPE_METHOD_ID_ITEM, len(methods_ordered), method_ids_off),
        (TYPE_CLASS_DEF_ITEM, 1, class_defs_off),
    ]
    if fields_ordered:
        map_items.append((TYPE_FIELD_ID_ITEM, len(fields_ordered), field_ids_off))
    if type_list_offsets:
        map_items.append((TYPE_TYPE_LIST, len(type_list_offsets), type_list_offsets[0]))
    map_items.extend(
        (
            (TYPE_CODE_ITEM, len(code_item_offsets), code_item_offsets[0]),
            (TYPE_CLASS_DATA_ITEM, 1, class_data_off),
            (TYPE_STRING_DATA_ITEM, len(strings_ordered), string_data_start),
            (TYPE_MAP_LIST, 1, map_off),
        )
    )
    map_items.sort(key=lambda item: item[2])
    data.extend(_u32(len(map_items)))
    for item_type, count, offset in map_items:
        data.extend(struct.pack("<HHII", item_type, 0, count, offset))

    data_size = len(data)
    file_size = data_off + data_size

    out = bytearray(b"\x00" * DEX_HEADER_SIZE)
    out[0:8] = DEX039_MAGIC
    struct.pack_into(
        "<20I",
        out,
        32,
        file_size,
        DEX_HEADER_SIZE,
        DEX_ENDIAN_CONSTANT,
        0,
        0,
        map_off,
        len(strings_ordered),
        string_ids_off,
        len(types_ordered),
        type_ids_off,
        len(protos_ordered),
        proto_ids_off,
        len(fields_ordered),
        field_ids_off,
        len(methods_ordered),
        method_ids_off,
        1,
        class_defs_off,
        data_size,
        data_off,
    )
    out.extend(b"".join(_u32(offset) for offset in string_offsets))
    out.extend(b"".join(_u32(string_idx[value]) for value in types_ordered))
    for proto in protos_ordered:
        out.extend(struct.pack("<III", string_idx[_shorty(proto)], type_idx[proto.return_type], parameter_offsets.get(proto.parameters, 0)))
    for owner, name, field_type in fields_ordered:
        out.extend(struct.pack("<HHI", type_idx[owner], type_idx[field_type], string_idx[name]))
    for owner, name, proto in methods_ordered:
        out.extend(struct.pack("<HHI", type_idx[owner], proto_idx[proto], string_idx[name]))
    out.extend(
        struct.pack(
            "<8I",
            type_idx[spec.class_descriptor],
            spec.class_access_flags,
            type_idx[spec.superclass_descriptor],
            interfaces_off,
            NO_INDEX,
            0,
            class_data_off,
            0,
        )
    )
    out.extend(data)
    if len(out) != file_size:
        raise AssertionError((len(out), file_size))

    out[12:32] = hashlib.sha1(out[32:]).digest()
    struct.pack_into("<I", out, 8, zlib.adler32(out[12:]) & 0xFFFFFFFF)
    return bytes(out)

def inspect_dex(data: bytes) -> DexInspection:
    """Parse enough of a DEX file to independently check the emitted container."""

    if len(data) < DEX_HEADER_SIZE or data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError("not a DEX file")
    if struct.unpack_from("<I", data, 36)[0] != DEX_HEADER_SIZE:
        raise ValueError("unexpected DEX header size")
    if struct.unpack_from("<I", data, 40)[0] != DEX_ENDIAN_CONSTANT:
        raise ValueError("unsupported DEX endian tag")
    fields = struct.unpack_from("<20I", data, 32)
    (
        file_size,
        _header_size,
        _endian,
        _link_size,
        _link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        _proto_ids_off,
        _field_ids_size,
        _field_ids_off,
        method_ids_size,
        _method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    ) = fields
    if file_size != len(data) or data_off + data_size != len(data):
        raise ValueError("DEX size fields do not cover the file")

    strings: list[str] = []
    for index in range(string_ids_size):
        offset = struct.unpack_from("<I", data, string_ids_off + index * 4)[0]
        units, cursor = _read_uleb(data, offset)
        end = data.find(b"\x00", cursor)
        if end < 0:
            raise ValueError("unterminated DEX string_data_item")
        strings.append(_mutf8_decode(data[cursor:end], units))
    if tuple(strings) != tuple(sorted(strings, key=_utf16_units)):
        raise ValueError("DEX string_ids are not canonically sorted")

    type_descriptors = tuple(strings[struct.unpack_from("<I", data, type_ids_off + index * 4)[0]] for index in range(type_ids_size))
    if class_defs_size != 1:
        raise ValueError("prototype DEX inspector expects exactly one class definition")
    class_idx, _access_flags, superclass_idx, interfaces_off = struct.unpack_from("<4I", data, class_defs_off)
    if class_idx >= len(type_descriptors) or superclass_idx >= len(type_descriptors):
        raise ValueError("DEX class type index out of bounds")
    interfaces: tuple[str, ...] = ()
    if interfaces_off:
        if interfaces_off + 4 > len(data):
            raise ValueError("DEX interface type_list out of bounds")
        interface_count = struct.unpack_from("<I", data, interfaces_off)[0]
        end = interfaces_off + 4 + 2 * interface_count
        if end > len(data):
            raise ValueError("DEX interface type_list truncated")
        interface_indices = struct.unpack_from(f"<{interface_count}H", data, interfaces_off + 4) if interface_count else ()
        if any(index >= len(type_descriptors) for index in interface_indices):
            raise ValueError("DEX interface type index out of bounds")
        interfaces = tuple(type_descriptors[index] for index in interface_indices)

    if map_off + 4 > len(data):
        raise ValueError("DEX map offset out of bounds")
    map_size = struct.unpack_from("<I", data, map_off)[0]
    map_items = tuple(
        (item_type, count, offset)
        for item_type, _unused, count, offset in (
            struct.unpack_from("<HHII", data, map_off + 4 + index * 12) for index in range(map_size)
        )
    )
    offsets = tuple(item[2] for item in map_items)
    if offsets != tuple(sorted(offsets)):
        raise ValueError("DEX map items are not ordered by offset")

    return DexInspection(
        data[4:7].decode("ascii"),
        file_size,
        string_ids_size,
        type_ids_size,
        proto_ids_size,
        method_ids_size,
        class_defs_size,
        data_size,
        map_items,
        tuple(strings),
        type_descriptors[class_idx],
        type_descriptors[superclass_idx],
        interfaces,
        struct.unpack_from("<I", data, 8)[0] == (zlib.adler32(data[12:]) & 0xFFFFFFFF),
        data[12:32] == hashlib.sha1(data[32:]).digest(),
    )


@dataclass(frozen=True)
class DexClassDef:
    descriptor: str
    superclass: str | None
    interfaces: tuple[str, ...]
    # (name, proto descriptor, access flags) for direct and virtual methods.
    methods: tuple[tuple[str, str, int], ...]


@dataclass(frozen=True)
class DexReferences:
    """Every class, method and field a DEX file defines or names.

    Method and field references are ``(class, name, descriptor)`` triples with
    JVM-style proto descriptors such as ``(Ljava/lang/String;)V``.
    """

    classes: tuple[DexClassDef, ...]
    method_refs: tuple[tuple[str, str, str], ...]
    field_refs: tuple[tuple[str, str, str], ...]
    types: tuple[str, ...]
    strings: tuple[str, ...]


def inspect_dex_references(data: bytes) -> DexReferences:
    """Read the reference tables of any DEX file, independent of the emitter."""

    view_strings: list[str] = []
    if len(data) < DEX_HEADER_SIZE or data[:4] != b"dex\n":
        raise ValueError("not a DEX file")
    (
        string_ids_size, string_ids_off, type_ids_size, type_ids_off, proto_ids_size, proto_ids_off,
        field_ids_size, field_ids_off, method_ids_size, method_ids_off, class_defs_size, class_defs_off,
    ) = struct.unpack_from("<12I", data, 56)
    for index in range(string_ids_size):
        offset = struct.unpack_from("<I", data, string_ids_off + index * 4)[0]
        units, cursor = _read_uleb(data, offset)
        end = data.find(b"\x00", cursor)
        if end < 0:
            raise ValueError("unterminated DEX string_data_item")
        view_strings.append(_mutf8_decode(data[cursor:end], units))
    types = tuple(view_strings[struct.unpack_from("<I", data, type_ids_off + index * 4)[0]] for index in range(type_ids_size))

    def type_list(offset: int) -> tuple[str, ...]:
        if not offset:
            return ()
        count = struct.unpack_from("<I", data, offset)[0]
        return tuple(types[index] for index in struct.unpack_from(f"<{count}H", data, offset + 4))

    protos = []
    for index in range(proto_ids_size):
        _shorty, return_idx, parameters_off = struct.unpack_from("<III", data, proto_ids_off + index * 12)
        protos.append("(" + "".join(type_list(parameters_off)) + ")" + types[return_idx])
    field_refs = []
    for index in range(field_ids_size):
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", data, field_ids_off + index * 8)
        field_refs.append((types[class_idx], view_strings[name_idx], types[type_idx]))
    method_refs = []
    for index in range(method_ids_size):
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, method_ids_off + index * 8)
        method_refs.append((types[class_idx], view_strings[name_idx], protos[proto_idx]))

    classes = []
    no_index = 0xFFFFFFFF
    for index in range(class_defs_size):
        class_idx, _access, superclass_idx, interfaces_off, _source, _annotations, class_data_off, _static = (
            struct.unpack_from("<8I", data, class_defs_off + index * 32)
        )
        methods: list[tuple[str, str, int]] = []
        if class_data_off:
            cursor = class_data_off
            counts = []
            for _ in range(4):
                value, cursor = _read_uleb(data, cursor)
                counts.append(value)
            for _ in range(counts[0] + counts[1]):
                _diff, cursor = _read_uleb(data, cursor)
                _flags, cursor = _read_uleb(data, cursor)
            for count in counts[2:]:
                method_idx = 0
                for _ in range(count):
                    diff, cursor = _read_uleb(data, cursor)
                    flags, cursor = _read_uleb(data, cursor)
                    _code, cursor = _read_uleb(data, cursor)
                    method_idx += diff
                    _owner, name, proto = method_refs[method_idx]
                    methods.append((name, proto, flags))
        classes.append(DexClassDef(
            types[class_idx],
            None if superclass_idx == no_index else types[superclass_idx],
            type_list(interfaces_off),
            tuple(methods),
        ))
    return DexReferences(tuple(classes), tuple(method_refs), tuple(field_refs), types, tuple(view_strings))


__all__ = [
    "ACC_NATIVE",
    "ACC_PRIVATE",
    "ACC_PROTECTED",
    "ACC_PUBLIC",
    "ACC_SUPER",
    "DEX039_MAGIC",
    "DexActivityUiSpec",
    "DexConstantStringMethod",
    "DexEchoStringMethod",
    "DexNullReturnOverride",
    "DexClickTextSpec",
    "DexLibxposedHookInterceptSpec",
    "DexLibxposedHookInstallSpec",
    "DexLibxposedModuleServicesSpec",
    "DexLibxposedRemotePreferencesSpec",
    "DexLibxposedHotReloadSpec",
    "DexLibxposedRemoteFilesSpec",
    "DexBridgeSpec",
    "DexForwardingOverride",
    "DexClassDef",
    "DexInspection",
    "DexReferences",
    "DexNativeMethod",
    "DexProto",
    "activity_bridge_spec",
    "activity_button_bridge_spec",
    "activity_button_resource_bridge_spec",
    "click_resource_listener_bridge_spec",
    "click_text_listener_bridge_spec",
    "interface_callback_bridge_spec",
    "emit_dex039_bridge",
    "inspect_dex",
    "inspect_dex_references",
]
