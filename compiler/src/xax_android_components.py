"""Bounded semantic Android component carriers and direct DEX lowering."""
from __future__ import annotations

from dataclasses import dataclass

from xax_compiler import Cursor, Kind, SemanticObject, fail, target, uleb
from xax_dex import (
    ACC_PRIVATE,
    ACC_PUBLIC,
    ACC_NATIVE,
    DexBridgeSpec,
    DexForwardingOverride,
    DexNativeMethod,
    DexNullReturnOverride,
    DexProto,
)


ANDROID_BROADCAST_RECEIVER_PREFIX = b"android-broadcast-receiver-v1"
ANDROID_SERVICE_PREFIX = b"android-service-v1"
ANDROID_APPLICATION_PREFIX = b"android-application-v1"


@dataclass(frozen=True)
class AndroidBroadcastReceiverDescription:
    class_descriptor: str
    exported: bool = False
    action: str | None = None

    def __post_init__(self) -> None:
        if not (self.class_descriptor.startswith("L") and self.class_descriptor.endswith(";") and "." not in self.class_descriptor):
            raise ValueError("BroadcastReceiver class identity must be a DEX class descriptor")
        if self.action is not None and (not self.action or "\x00" in self.action):
            raise ValueError("BroadcastReceiver action must be nonempty and NUL-free")

    @property
    def java_class_name(self) -> str:
        return self.class_descriptor[1:-1].replace("/", ".")


def android_broadcast_receiver_semantics(
    *,
    class_descriptor: str = "Lxax/generated/XaxReceiver;",
    exported: bool = False,
    action: str | None = None,
) -> SemanticObject:
    description = AndroidBroadcastReceiverDescription(class_descriptor, exported, action)
    descriptor = description.class_descriptor.encode("utf-8")
    action_raw = b"" if description.action is None else description.action.encode("utf-8")
    identity = bytearray(ANDROID_BROADCAST_RECEIVER_PREFIX)
    identity.extend(uleb(len(descriptor)) + descriptor)
    identity.append(1 if description.exported else 0)
    identity.extend(uleb(len(action_raw)) + action_raw)
    return target(bytes(identity))


def decode_android_broadcast_receiver(obj: SemanticObject) -> AndroidBroadcastReceiverDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-RECEIVER-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-RECEIVER-CARRIER")
    if not identity.startswith(ANDROID_BROADCAST_RECEIVER_PREFIX):
        fail(
            "XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-RECEIVER-IDENTITY",
            ANDROID_BROADCAST_RECEIVER_PREFIX.decode(), identity[:40].hex(),
        )
    cursor = Cursor(identity[len(ANDROID_BROADCAST_RECEIVER_PREFIX):], obj.cid.hex())
    try:
        descriptor = cursor.byte_string().decode("utf-8")
        exported = cursor.boolean()
        action_raw = cursor.byte_string()
        action = action_raw.decode("utf-8") if action_raw else None
        cursor.end("ANDROID-RECEIVER-IDENTITY")
        description = AndroidBroadcastReceiverDescription(descriptor, exported, action)
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-RECEIVER-FIELDS", "valid receiver fields", str(error))
    canonical = android_broadcast_receiver_semantics(
        class_descriptor=description.class_descriptor,
        exported=description.exported,
        action=description.action,
    )
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-RECEIVER-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


def lower_android_broadcast_receiver(obj: SemanticObject) -> DexBridgeSpec:
    """Lower one receiver to constructor + onReceive -> private native XAX callback."""

    description = decode_android_broadcast_receiver(obj)
    proto = DexProto("V", ("Landroid/content/Context;", "Landroid/content/Intent;"))
    native_name = "xaxOnReceive"
    return DexBridgeSpec(
        description.class_descriptor,
        "Landroid/content/BroadcastReceiver;",
        (DexNativeMethod(native_name, proto, ACC_PRIVATE | ACC_NATIVE),),
        (DexForwardingOverride("onReceive", proto, native_name, ACC_PUBLIC, False),),
        native_library="xaxapp",
    )


@dataclass(frozen=True)
class AndroidApplicationDescription:
    class_descriptor: str

    def __post_init__(self) -> None:
        if not (self.class_descriptor.startswith("L") and self.class_descriptor.endswith(";") and "." not in self.class_descriptor):
            raise ValueError("Application class identity must be a DEX class descriptor")

    @property
    def java_class_name(self) -> str:
        return self.class_descriptor[1:-1].replace("/", ".")


def android_application_semantics(
    *,
    class_descriptor: str = "Lxax/generated/XaxApplication;",
) -> SemanticObject:
    description = AndroidApplicationDescription(class_descriptor)
    descriptor = description.class_descriptor.encode("utf-8")
    identity = bytearray(ANDROID_APPLICATION_PREFIX)
    identity.extend(uleb(len(descriptor)) + descriptor)
    return target(bytes(identity))


def decode_android_application(obj: SemanticObject) -> AndroidApplicationDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-APPLICATION-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-APPLICATION-CARRIER")
    if not identity.startswith(ANDROID_APPLICATION_PREFIX):
        fail(
            "XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-APPLICATION-IDENTITY",
            ANDROID_APPLICATION_PREFIX.decode(), identity[:40].hex(),
        )
    cursor = Cursor(identity[len(ANDROID_APPLICATION_PREFIX):], obj.cid.hex())
    try:
        descriptor = cursor.byte_string().decode("utf-8")
        cursor.end("ANDROID-APPLICATION-IDENTITY")
        description = AndroidApplicationDescription(descriptor)
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-APPLICATION-FIELDS", "valid application fields", str(error))
    canonical = android_application_semantics(class_descriptor=description.class_descriptor)
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-APPLICATION-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


def lower_android_application(obj: SemanticObject) -> DexBridgeSpec:
    """Lower one Application to lifecycle-correct onCreate -> XAX."""

    description = decode_android_application(obj)
    proto = DexProto("V", ())
    return DexBridgeSpec(
        description.class_descriptor,
        "Landroid/app/Application;",
        (DexNativeMethod("xaxOnCreate", proto, ACC_PRIVATE | ACC_NATIVE),),
        (DexForwardingOverride("onCreate", proto, "xaxOnCreate", ACC_PUBLIC, True),),
        native_library="xaxapp",
    )


@dataclass(frozen=True)
class AndroidServiceDescription:
    class_descriptor: str
    exported: bool = False

    def __post_init__(self) -> None:
        if not (self.class_descriptor.startswith("L") and self.class_descriptor.endswith(";") and "." not in self.class_descriptor):
            raise ValueError("Service class identity must be a DEX class descriptor")

    @property
    def java_class_name(self) -> str:
        return self.class_descriptor[1:-1].replace("/", ".")


def android_service_semantics(
    *,
    class_descriptor: str = "Lxax/generated/XaxService;",
    exported: bool = False,
) -> SemanticObject:
    description = AndroidServiceDescription(class_descriptor, exported)
    descriptor = description.class_descriptor.encode("utf-8")
    identity = bytearray(ANDROID_SERVICE_PREFIX)
    identity.extend(uleb(len(descriptor)) + descriptor)
    identity.append(1 if description.exported else 0)
    return target(bytes(identity))


def decode_android_service(obj: SemanticObject) -> AndroidServiceDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-SERVICE-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-SERVICE-CARRIER")
    if not identity.startswith(ANDROID_SERVICE_PREFIX):
        fail(
            "XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-SERVICE-IDENTITY",
            ANDROID_SERVICE_PREFIX.decode(), identity[:40].hex(),
        )
    cursor = Cursor(identity[len(ANDROID_SERVICE_PREFIX):], obj.cid.hex())
    try:
        descriptor = cursor.byte_string().decode("utf-8")
        exported = cursor.boolean()
        cursor.end("ANDROID-SERVICE-IDENTITY")
        description = AndroidServiceDescription(descriptor, exported)
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-SERVICE-FIELDS", "valid service fields", str(error))
    canonical = android_service_semantics(
        class_descriptor=description.class_descriptor,
        exported=description.exported,
    )
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.COMPONENT", obj.cid.hex(), "ANDROID-SERVICE-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


def lower_android_service(obj: SemanticObject) -> DexBridgeSpec:
    """Lower one unbound Service to lifecycle callbacks plus managed null onBind.

    ``onCreate`` and ``onDestroy`` call their superclass implementations and then
    cross into XAX exactly once. ``onBind(Intent)`` returns null entirely in DEX,
    making the generated concrete Service valid without pretending Binder result
    lowering is implemented.
    """

    description = decode_android_service(obj)
    void_proto = DexProto("V", ())
    bind_proto = DexProto("Landroid/os/IBinder;", ("Landroid/content/Intent;",))
    return DexBridgeSpec(
        description.class_descriptor,
        "Landroid/app/Service;",
        (
            DexNativeMethod("xaxOnCreate", void_proto, ACC_PRIVATE | ACC_NATIVE),
            DexNativeMethod("xaxOnDestroy", void_proto, ACC_PRIVATE | ACC_NATIVE),
        ),
        (
            DexForwardingOverride("onCreate", void_proto, "xaxOnCreate", ACC_PUBLIC, True),
            DexForwardingOverride("onDestroy", void_proto, "xaxOnDestroy", ACC_PUBLIC, True),
        ),
        native_library="xaxapp",
        null_return_overrides=(DexNullReturnOverride("onBind", bind_proto, ACC_PUBLIC),),
    )


__all__ = [
    "ANDROID_BROADCAST_RECEIVER_PREFIX",
    "ANDROID_SERVICE_PREFIX",
    "ANDROID_APPLICATION_PREFIX",
    "AndroidBroadcastReceiverDescription",
    "AndroidServiceDescription",
    "AndroidApplicationDescription",
    "android_broadcast_receiver_semantics",
    "decode_android_broadcast_receiver",
    "lower_android_broadcast_receiver",
    "android_service_semantics",
    "decode_android_service",
    "lower_android_service",
    "android_application_semantics",
    "decode_android_application",
    "lower_android_application",
]
