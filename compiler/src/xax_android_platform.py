"""Android platform capability contracts: NDK ownership and SDK permission/callback rules (ADR-204).

Two halves, neither in the semantic kernel:

* NDK C contracts (``libandroid.so``, ``libmediandk.so``, ``libaaudio.so``) are
  ordinary typed foreign declarations whose native objects carry linear
  resource tokens, so the existing verifier rejects a leaked or doubly
  released window, codec, format or audio stream.  The machine ABI receives
  only the C arguments; tokens and effects are erased.
* SDK capabilities are a fixed table of exact Java members (owner, name, JVM
  descriptor), the manifest permissions they need, the member that releases
  what another acquires, and the abstract methods of the callback types the
  platform calls.  ``check_managed_platform_usage`` applies it to a
  managed-class APK (ADR-199) at build time: every JNI member or NDK symbol
  the exports can reach must have its permissions declared, an acquiring
  member must be paired with its release member, and a managed class that
  extends or implements a listed callback type must implement every abstract
  method (otherwise ART throws ``AbstractMethodError`` at the first callback).

Permission rules are manifest facts only.  Whether a user granted a runtime
permission is observed at run time through ``checkSelfPermission`` and
``onRequestPermissionsResult``, both listed below.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from xax_compiler import (
    EffectDomain,
    Kind,
    Permission,
    ResourceFlags,
    SemanticObject,
    bits_type,
    effect_type,
    fail,
    foreign_function_symbol,
    memory_effect_type,
    opaque_identity_type,
    pointer_type,
    resource_type,
)
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_memory_effect_type, jni_reference_type

# Linear resource kinds for NDK objects (POSIX descriptors are 0x102, Win32 threads 0x103).
ANATIVEWINDOW_RESOURCE_KIND = 0x110
AMEDIAFORMAT_RESOURCE_KIND = 0x111
AMEDIACODEC_RESOURCE_KIND = 0x112
AAUDIO_BUILDER_RESOURCE_KIND = 0x113
AAUDIO_STREAM_RESOURCE_KIND = 0x114
AAUDIO_OUTPUT, AAUDIO_INPUT = 0, 1  # resource instance and AAUDIO_DIRECTION_* value


def _handle(identity: bytes) -> SemanticObject:
    """An opaque native handle pointer; only the platform dereferences it."""
    return pointer_type(opaque_identity_type(identity), Permission.READ_WRITE, 8, space=2)


# ---------------------------------------------------------------------------
# NDK contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NativeWindowApi:
    """``ANativeWindow`` from a Java ``Surface`` (API 14+), released exactly once.

    ``fromSurface`` returns NULL only for an invalid Surface; the caller
    branches on the handle before ``release`` because releasing NULL is not
    defined by the NDK.  The SurfaceHolder contract still applies: release the
    window before ``surfaceDestroyed`` returns.
    """

    window: SemanticObject
    token: SemanticObject
    from_surface: SemanticObject
    release: SemanticObject
    set_buffers_geometry: SemanticObject
    get_width: SemanticObject
    get_height: SemanticObject

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (self.from_surface, self.release, self.set_buffers_geometry, self.get_width, self.get_height)


def native_window_api() -> NativeWindowApi:
    b32 = bits_type(32)
    window = _handle(b"android.ndk.ANativeWindow")
    token = resource_type(ANATIVEWINDOW_RESOURCE_KIND, 1, flags=ResourceFlags.LINEAR)
    device = effect_type(EffectDomain.DEVICE, 0)
    surface = jni_reference_type(JniReferenceKind.BORROWED, b"android.view.Surface", loader_domain=b"android.boot")
    jni = jni_memory_effect_type()
    lib = b"libandroid.so"
    return NativeWindowApi(
        window,
        token,
        foreign_function_symbol(lib, b"ANativeWindow_fromSurface", (jni_env_pointer_type(), surface, jni, device), (window, token, jni, device)),
        foreign_function_symbol(lib, b"ANativeWindow_release", (window, token, device), (device,)),
        # The token is borrowed: passed in and handed back unchanged.
        foreign_function_symbol(lib, b"ANativeWindow_setBuffersGeometry", (window, b32, b32, b32, token, device), (b32, token, device)),
        foreign_function_symbol(lib, b"ANativeWindow_getWidth", (window, token, device), (b32, token, device)),
        foreign_function_symbol(lib, b"ANativeWindow_getHeight", (window, token, device), (b32, token, device)),
    )


@dataclass(frozen=True)
class MediaCodecApi:
    """``AMediaCodec``/``AMediaFormat`` (``libmediandk.so``, API 21+).

    ``delete`` accepts NULL (NDK source: ``delete`` of a null object), so a
    failed create still releases soundly.  Input buffers are platform-owned:
    ``getInputBuffer`` writes the capacity to ``out_size`` and the returned
    pointer is valid until ``queueInputBuffer`` for that index; it is not a
    bounds-proven view (open issue OI-47).  ``AMediaCodecBufferInfo`` is
    24 bytes: int32 offset, int32 size, int64 presentationTimeUs, uint32 flags.
    """

    codec: SemanticObject
    codec_token: SemanticObject
    format: SemanticObject
    format_token: SemanticObject
    format_new: SemanticObject
    format_set_string: SemanticObject
    format_set_int32: SemanticObject
    format_delete: SemanticObject
    create_decoder_by_type: SemanticObject
    create_encoder_by_type: SemanticObject
    configure_surface: SemanticObject
    configure_buffers: SemanticObject
    start: SemanticObject
    dequeue_input_buffer: SemanticObject
    get_input_buffer: SemanticObject
    queue_input_buffer: SemanticObject
    dequeue_output_buffer: SemanticObject
    release_output_buffer: SemanticObject
    stop: SemanticObject
    delete: SemanticObject

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return tuple(getattr(self, name) for name in self.__dataclass_fields__ if name not in ("codec", "codec_token", "format", "format_token"))


BUFFER_INFO_BYTES = 24


def media_codec_api(window: NativeWindowApi | None = None) -> MediaCodecApi:
    window = window or native_window_api()
    b8, b32, b64 = bits_type(8), bits_type(32), bits_type(64)
    rd = pointer_type(b8, Permission.READ, 1, space=2)
    rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
    codec, fmt = _handle(b"android.ndk.AMediaCodec"), _handle(b"android.ndk.AMediaFormat")
    codec_token = resource_type(AMEDIACODEC_RESOURCE_KIND, 1, flags=ResourceFlags.LINEAR)
    format_token = resource_type(AMEDIAFORMAT_RESOURCE_KIND, 1, flags=ResourceFlags.LINEAR)
    device, memory = effect_type(EffectDomain.DEVICE, 0), memory_effect_type()
    lib = b"libmediandk.so"

    def sym(name, inputs, outputs):
        return foreign_function_symbol(lib, name, inputs, outputs)

    return MediaCodecApi(
        codec, codec_token, fmt, format_token,
        sym(b"AMediaFormat_new", (device,), (fmt, format_token, device)),
        sym(b"AMediaFormat_setString", (fmt, rd, rd, format_token, device), (format_token, device)),
        sym(b"AMediaFormat_setInt32", (fmt, rd, b32, format_token, device), (format_token, device)),
        sym(b"AMediaFormat_delete", (fmt, format_token, device), (b32, device)),
        sym(b"AMediaCodec_createDecoderByType", (rd, device), (codec, codec_token, device)),
        sym(b"AMediaCodec_createEncoderByType", (rd, device), (codec, codec_token, device)),
        # configure(codec, format, surface, crypto, flags): decode to a borrowed window...
        sym(b"AMediaCodec_configure", (codec, fmt, window.window, b64, b32, codec_token, format_token, window.token, device),
            (b32, codec_token, format_token, window.token, device)),
        # ...or to buffers (surface and crypto are the null word 0).
        sym(b"AMediaCodec_configure", (codec, fmt, b64, b64, b32, codec_token, format_token, device), (b32, codec_token, format_token, device)),
        sym(b"AMediaCodec_start", (codec, codec_token, device), (b32, codec_token, device)),
        sym(b"AMediaCodec_dequeueInputBuffer", (codec, b64, codec_token, device), (b64, codec_token, device)),
        sym(b"AMediaCodec_getInputBuffer", (codec, b64, rw, codec_token, device, memory), (rw, codec_token, device, memory)),
        sym(b"AMediaCodec_queueInputBuffer", (codec, b64, b64, b64, b64, b32, codec_token, device), (b32, codec_token, device)),
        sym(b"AMediaCodec_dequeueOutputBuffer", (codec, rw, b64, codec_token, device, memory), (b64, codec_token, device, memory)),
        sym(b"AMediaCodec_releaseOutputBuffer", (codec, b64, b8, codec_token, device), (b32, codec_token, device)),
        sym(b"AMediaCodec_stop", (codec, codec_token, device), (b32, codec_token, device)),
        sym(b"AMediaCodec_delete", (codec, codec_token, device), (b32, device)),
    )


@dataclass(frozen=True)
class AAudioApi:
    """One AAudio direction (``libaaudio.so``, API 26+): output plays, input captures.

    The direction is part of the builder and stream token types, so a stream
    opened from an input builder can only ``read`` and an output stream can
    only ``write``.  The program still sets the platform direction with
    ``set_direction(builder, AAUDIO_DIRECTION_INPUT=1)``; an input build that
    forgot it gets an output stream whose ``read`` returns
    ``AAUDIO_ERROR_UNIMPLEMENTED`` (a safe error, not undefined behaviour).
    Input requires ``android.permission.RECORD_AUDIO``
    (``check_managed_platform_usage``).  ``timeout`` is nanoseconds; results are
    frame counts or negative ``aaudio_result_t`` errors.
    """

    direction: int
    builder: SemanticObject
    builder_token: SemanticObject
    stream: SemanticObject
    stream_token: SemanticObject
    create_stream_builder: SemanticObject
    set_direction: SemanticObject
    set_sample_rate: SemanticObject
    set_channel_count: SemanticObject
    set_format: SemanticObject
    set_performance_mode: SemanticObject
    open_stream: SemanticObject
    builder_delete: SemanticObject
    request_start: SemanticObject
    request_stop: SemanticObject
    transfer: SemanticObject  # AAudioStream_write (output) or AAudioStream_read (input)
    close: SemanticObject

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return tuple(getattr(self, name) for name in self.__dataclass_fields__
                     if name not in ("direction", "builder", "builder_token", "stream", "stream_token"))


def aaudio_api(direction: int = AAUDIO_OUTPUT) -> AAudioApi:
    if direction not in (AAUDIO_OUTPUT, AAUDIO_INPUT):
        raise ValueError("AAudio direction is output (0) or input (1)")
    b8, b32, b64 = bits_type(8), bits_type(32), bits_type(64)
    rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
    rd = pointer_type(b8, Permission.READ, 1, space=2)
    # AAudio hands its handles back through out-parameters, so a handle is the 64-bit word the
    # program loads from its own stack cell; the linear token carries the object's type.
    builder = stream = b64
    cell = pointer_type(b64, Permission.READ_WRITE, 8)
    builder_token = resource_type(AAUDIO_BUILDER_RESOURCE_KIND, 1, flags=ResourceFlags.LINEAR, instance=direction)
    stream_token = resource_type(AAUDIO_STREAM_RESOURCE_KIND, 1, flags=ResourceFlags.LINEAR, instance=direction)
    device, memory = effect_type(EffectDomain.DEVICE, 0), memory_effect_type()
    lib = b"libaaudio.so"

    def sym(name, inputs, outputs):
        return foreign_function_symbol(lib, name, inputs, outputs)

    def setter(name):
        return sym(name, (builder, b32, builder_token, device), (builder_token, device))

    if direction == AAUDIO_OUTPUT:
        transfer = sym(b"AAudioStream_write", (stream, rd, b32, b64, stream_token, device, memory), (b32, stream_token, device, memory))
    else:
        transfer = sym(b"AAudioStream_read", (stream, rw, b32, b64, stream_token, device, memory), (b32, stream_token, device, memory))
    return AAudioApi(
        direction, builder, builder_token, stream, stream_token,
        # AAudio_createStreamBuilder(&builder) writes the handle; the program loads it.
        sym(b"AAudio_createStreamBuilder", (cell, device, memory), (b32, builder_token, device, memory)),
        setter(b"AAudioStreamBuilder_setDirection"),
        setter(b"AAudioStreamBuilder_setSampleRate"),
        setter(b"AAudioStreamBuilder_setChannelCount"),
        setter(b"AAudioStreamBuilder_setFormat"),
        setter(b"AAudioStreamBuilder_setPerformanceMode"),
        sym(b"AAudioStreamBuilder_openStream", (builder, cell, builder_token, device, memory), (b32, builder_token, stream_token, device, memory)),
        sym(b"AAudioStreamBuilder_delete", (builder, builder_token, device), (b32, device)),
        sym(b"AAudioStream_requestStart", (stream, stream_token, device), (b32, stream_token, device)),
        sym(b"AAudioStream_requestStop", (stream, stream_token, device), (b32, stream_token, device)),
        transfer,
        sym(b"AAudioStream_close", (stream, stream_token, device), (b32, device)),
    )


def ndk_type_objects() -> tuple[SemanticObject, ...]:
    """Every type the NDK contracts reference, for building a closed store."""
    from xax_jni import jni_type_objects

    window = native_window_api()
    items: list[SemanticObject] = [
        bits_type(8), bits_type(32), bits_type(64), effect_type(EffectDomain.DEVICE, 0), memory_effect_type(),
        pointer_type(bits_type(8), Permission.READ, 1, space=2), pointer_type(bits_type(8), Permission.READ_WRITE, 1, space=2),
        window.window, window.token, *jni_type_objects(((JniReferenceKind.BORROWED, b"android.view.Surface", b"android.boot"),)),
    ]
    items.append(pointer_type(bits_type(64), Permission.READ_WRITE, 8))
    for identity in (b"android.ndk.ANativeWindow", b"android.ndk.AMediaCodec", b"android.ndk.AMediaFormat"):
        items += [opaque_identity_type(identity), _handle(identity)]
    codec = media_codec_api(window)
    items += [codec.codec_token, codec.format_token]
    for direction in (AAUDIO_OUTPUT, AAUDIO_INPUT):
        audio = aaudio_api(direction)
        items += [audio.builder_token, audio.stream_token]
    return tuple({item.cid: item for item in items}.values())


# ---------------------------------------------------------------------------
# SDK capability table
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class PermissionRule:
    """``permission`` must be declared when ``target_sdk >= from_target`` and the app can run on
    an API level ``<= device_max`` (0: any level).  A declared ``maxSdkVersion`` must cover it."""

    permission: str
    from_target: int = 1
    device_max: int = 0


@dataclass(frozen=True)
class SdkMember:
    owner: str  # internal name, e.g. "android/bluetooth/BluetoothAdapter"
    name: str
    descriptor: str
    static: bool = False


@dataclass(frozen=True)
class AndroidCapability:
    name: str
    members: tuple[SdkMember, ...]
    permissions: tuple[PermissionRule, ...] = ()
    releases: tuple[tuple[SdkMember, SdkMember], ...] = ()  # (acquire, release)
    min_api: int = 1


def _m(owner: str, name: str, descriptor: str, static: bool = False) -> SdkMember:
    return SdkMember(owner, name, descriptor, static)


_P = "android.permission."
_BT_CONNECT = (PermissionRule(_P + "BLUETOOTH_CONNECT", 31), PermissionRule(_P + "BLUETOOTH", 1, 30))
_BT_SCAN = (PermissionRule(_P + "BLUETOOTH_SCAN", 31), PermissionRule(_P + "BLUETOOTH_ADMIN", 1, 30),
            PermissionRule(_P + "ACCESS_FINE_LOCATION", 1, 30))
_NEARBY_WIFI = (PermissionRule(_P + "NEARBY_WIFI_DEVICES", 33), PermissionRule(_P + "ACCESS_FINE_LOCATION", 1, 32))
_BT_SOCKET = "android/bluetooth/BluetoothSocket"
_BT_SERVER = "android/bluetooth/BluetoothServerSocket"
_CODEC = "android/media/MediaCodec"
_P2P = "android/net/wifi/p2p/WifiP2pManager"
_CHANNEL = "Landroid/net/wifi/p2p/WifiP2pManager$Channel;"

CAPABILITIES: tuple[AndroidCapability, ...] = (
    AndroidCapability("runtime-permissions", (
        _m("android/content/Context", "checkSelfPermission", "(Ljava/lang/String;)I"),
        _m("android/app/Activity", "requestPermissions", "([Ljava/lang/String;I)V"),
        _m("android/app/Activity", "shouldShowRequestPermissionRationale", "(Ljava/lang/String;)Z"),
    ), min_api=23),
    AndroidCapability("foreground-service", (
        _m("android/app/Service", "startForeground", "(ILandroid/app/Notification;I)V"),
        _m("android/app/Service", "stopForeground", "(I)V"),
        _m("android/app/NotificationManager", "createNotificationChannel", "(Landroid/app/NotificationChannel;)V"),
        _m("android/app/Notification$Builder", "<init>", "(Landroid/content/Context;Ljava/lang/String;)V"),
        _m("android/app/Notification$Builder", "build", "()Landroid/app/Notification;"),
    ), (PermissionRule(_P + "FOREGROUND_SERVICE", 28), PermissionRule(_P + "POST_NOTIFICATIONS", 33)), min_api=29),
    AndroidCapability("bluetooth-adapter", (
        _m("android/bluetooth/BluetoothManager", "getAdapter", "()Landroid/bluetooth/BluetoothAdapter;"),
        _m("android/bluetooth/BluetoothAdapter", "isEnabled", "()Z"),
    ), (PermissionRule(_P + "BLUETOOTH", 1, 30),), min_api=18),
    AndroidCapability("bluetooth-paired-devices", (
        _m("android/bluetooth/BluetoothAdapter", "getBondedDevices", "()Ljava/util/Set;"),
        _m("android/bluetooth/BluetoothDevice", "getAddress", "()Ljava/lang/String;"),
        _m("android/bluetooth/BluetoothDevice", "getName", "()Ljava/lang/String;"),
    ), _BT_CONNECT),
    AndroidCapability("bluetooth-discovery", (
        _m("android/bluetooth/BluetoothAdapter", "startDiscovery", "()Z"),
        _m("android/bluetooth/BluetoothAdapter", "cancelDiscovery", "()Z"),
    ), _BT_SCAN, ((_m("android/bluetooth/BluetoothAdapter", "startDiscovery", "()Z"), _m("android/bluetooth/BluetoothAdapter", "cancelDiscovery", "()Z")),)),
    # listenUsing*WithServiceRecord registers the SDP record that names the UUID; closing the
    # server socket removes it.
    AndroidCapability("bluetooth-sdp-rfcomm-server", (
        _m("android/bluetooth/BluetoothAdapter", "listenUsingRfcommWithServiceRecord", "(Ljava/lang/String;Ljava/util/UUID;)Landroid/bluetooth/BluetoothServerSocket;"),
        _m("android/bluetooth/BluetoothAdapter", "listenUsingInsecureRfcommWithServiceRecord", "(Ljava/lang/String;Ljava/util/UUID;)Landroid/bluetooth/BluetoothServerSocket;"),
        _m(_BT_SERVER, "accept", "(I)Landroid/bluetooth/BluetoothSocket;"),
        _m(_BT_SERVER, "close", "()V"),
        _m("java/util/UUID", "fromString", "(Ljava/lang/String;)Ljava/util/UUID;", True),
    ), _BT_CONNECT, (
        (_m("android/bluetooth/BluetoothAdapter", "listenUsingRfcommWithServiceRecord", "(Ljava/lang/String;Ljava/util/UUID;)Landroid/bluetooth/BluetoothServerSocket;"), _m(_BT_SERVER, "close", "()V")),
        (_m("android/bluetooth/BluetoothAdapter", "listenUsingInsecureRfcommWithServiceRecord", "(Ljava/lang/String;Ljava/util/UUID;)Landroid/bluetooth/BluetoothServerSocket;"), _m(_BT_SERVER, "close", "()V")),
        (_m(_BT_SERVER, "accept", "(I)Landroid/bluetooth/BluetoothSocket;"), _m(_BT_SOCKET, "close", "()V")),
    )),
    AndroidCapability("bluetooth-rfcomm-client", (
        _m("android/bluetooth/BluetoothDevice", "createRfcommSocketToServiceRecord", "(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;"),
        _m(_BT_SOCKET, "connect", "()V"),
        _m(_BT_SOCKET, "getInputStream", "()Ljava/io/InputStream;"),
        _m(_BT_SOCKET, "getOutputStream", "()Ljava/io/OutputStream;"),
        _m(_BT_SOCKET, "close", "()V"),
        _m("java/io/InputStream", "read", "([BII)I"),
        _m("java/io/OutputStream", "write", "([BII)V"),
    ), _BT_CONNECT, ((_m("android/bluetooth/BluetoothDevice", "createRfcommSocketToServiceRecord", "(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;"), _m(_BT_SOCKET, "close", "()V")),)),
    AndroidCapability("network-callbacks", (
        _m("android/net/ConnectivityManager", "registerNetworkCallback", "(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V"),
        _m("android/net/ConnectivityManager", "unregisterNetworkCallback", "(Landroid/net/ConnectivityManager$NetworkCallback;)V"),
        _m("android/net/NetworkCapabilities", "hasTransport", "(I)Z"),
        _m("android/net/Network", "getNetworkHandle", "()J"),
    ), (PermissionRule(_P + "ACCESS_NETWORK_STATE"),), (
        (_m("android/net/ConnectivityManager", "registerNetworkCallback", "(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V"),
         _m("android/net/ConnectivityManager", "unregisterNetworkCallback", "(Landroid/net/ConnectivityManager$NetworkCallback;)V")),
    ), min_api=24),
    AndroidCapability("network-request", (
        _m("android/net/ConnectivityManager", "requestNetwork", "(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V"),
    ), (PermissionRule(_P + "CHANGE_NETWORK_STATE"), PermissionRule(_P + "ACCESS_NETWORK_STATE")), (
        (_m("android/net/ConnectivityManager", "requestNetwork", "(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V"),
         _m("android/net/ConnectivityManager", "unregisterNetworkCallback", "(Landroid/net/ConnectivityManager$NetworkCallback;)V")),
    ), min_api=21),
    AndroidCapability("wifi-direct", (
        _m(_P2P, "initialize", "(Landroid/content/Context;Landroid/os/Looper;Landroid/net/wifi/p2p/WifiP2pManager$ChannelListener;)" + _CHANNEL),
        _m(_P2P, "createGroup", f"({_CHANNEL}Landroid/net/wifi/p2p/WifiP2pManager$ActionListener;)V"),
        _m(_P2P, "removeGroup", f"({_CHANNEL}Landroid/net/wifi/p2p/WifiP2pManager$ActionListener;)V"),
        _m(_P2P, "requestGroupInfo", f"({_CHANNEL}Landroid/net/wifi/p2p/WifiP2pManager$GroupInfoListener;)V"),
        _m("android/net/wifi/p2p/WifiP2pManager$Channel", "close", "()V"),
        _m("android/net/wifi/p2p/WifiP2pGroup", "getNetworkName", "()Ljava/lang/String;"),
        _m("android/net/wifi/p2p/WifiP2pGroup", "getPassphrase", "()Ljava/lang/String;"),
    ), (PermissionRule(_P + "ACCESS_WIFI_STATE"), PermissionRule(_P + "CHANGE_WIFI_STATE"), *_NEARBY_WIFI), (
        (_m(_P2P, "initialize", "(Landroid/content/Context;Landroid/os/Looper;Landroid/net/wifi/p2p/WifiP2pManager$ChannelListener;)" + _CHANNEL),
         _m("android/net/wifi/p2p/WifiP2pManager$Channel", "close", "()V")),
        (_m(_P2P, "createGroup", f"({_CHANNEL}Landroid/net/wifi/p2p/WifiP2pManager$ActionListener;)V"),
         _m(_P2P, "removeGroup", f"({_CHANNEL}Landroid/net/wifi/p2p/WifiP2pManager$ActionListener;)V")),
    ), min_api=27),
    # A local-only hotspot is a reservation the app holds until it closes it; arbitrary
    # tethering configuration is not an app capability and is not offered.
    AndroidCapability("local-only-hotspot", (
        _m("android/net/wifi/WifiManager", "startLocalOnlyHotspot", "(Landroid/net/wifi/WifiManager$LocalOnlyHotspotCallback;Landroid/os/Handler;)V"),
        _m("android/net/wifi/WifiManager$LocalOnlyHotspotReservation", "getSoftApConfiguration", "()Landroid/net/wifi/SoftApConfiguration;"),
        _m("android/net/wifi/WifiManager$LocalOnlyHotspotReservation", "close", "()V"),
    ), (PermissionRule(_P + "CHANGE_WIFI_STATE"), *_NEARBY_WIFI), min_api=30),
    AndroidCapability("tls-sslengine", (
        _m("javax/net/ssl/SSLContext", "getInstance", "(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;", True),
        _m("javax/net/ssl/SSLContext", "init", "([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V"),
        _m("javax/net/ssl/SSLContext", "createSSLEngine", "(Ljava/lang/String;I)Ljavax/net/ssl/SSLEngine;"),
        _m("javax/net/ssl/SSLEngine", "setUseClientMode", "(Z)V"),
        _m("javax/net/ssl/SSLEngine", "beginHandshake", "()V"),
        _m("javax/net/ssl/SSLEngine", "wrap", "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)Ljavax/net/ssl/SSLEngineResult;"),
        _m("javax/net/ssl/SSLEngine", "unwrap", "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)Ljavax/net/ssl/SSLEngineResult;"),
        _m("javax/net/ssl/SSLEngine", "getHandshakeStatus", "()Ljavax/net/ssl/SSLEngineResult$HandshakeStatus;"),
        _m("javax/net/ssl/SSLEngine", "getDelegatedTask", "()Ljava/lang/Runnable;"),
        _m("javax/net/ssl/SSLEngine", "getSession", "()Ljavax/net/ssl/SSLSession;"),
        _m("javax/net/ssl/SSLEngine", "closeOutbound", "()V"),
        _m("javax/net/ssl/SSLEngine", "closeInbound", "()V"),
        _m("javax/net/ssl/SSLSession", "getPacketBufferSize", "()I"),
        _m("javax/net/ssl/SSLSession", "getApplicationBufferSize", "()I"),
        _m("javax/net/ssl/SSLEngineResult", "getStatus", "()Ljavax/net/ssl/SSLEngineResult$Status;"),
        _m("javax/net/ssl/SSLEngineResult", "bytesConsumed", "()I"),
        _m("javax/net/ssl/SSLEngineResult", "bytesProduced", "()I"),
    ), (PermissionRule(_P + "INTERNET"),), (
        (_m("javax/net/ssl/SSLEngine", "beginHandshake", "()V"), _m("javax/net/ssl/SSLEngine", "closeOutbound", "()V")),
    )),
    AndroidCapability("media-codec-java", (
        _m(_CODEC, "createDecoderByType", "(Ljava/lang/String;)Landroid/media/MediaCodec;", True),
        _m(_CODEC, "configure", "(Landroid/media/MediaFormat;Landroid/view/Surface;Landroid/media/MediaCrypto;I)V"),
        _m(_CODEC, "start", "()V"),
        _m(_CODEC, "dequeueInputBuffer", "(J)I"),
        _m(_CODEC, "getInputBuffer", "(I)Ljava/nio/ByteBuffer;"),
        _m(_CODEC, "queueInputBuffer", "(IIIJI)V"),
        _m(_CODEC, "dequeueOutputBuffer", "(Landroid/media/MediaCodec$BufferInfo;J)I"),
        _m(_CODEC, "releaseOutputBuffer", "(IZ)V"),
        _m(_CODEC, "stop", "()V"),
        _m(_CODEC, "release", "()V"),
    ), (), ((_m(_CODEC, "createDecoderByType", "(Ljava/lang/String;)Landroid/media/MediaCodec;", True), _m(_CODEC, "release", "()V")),), min_api=21),
    AndroidCapability("surface-holder", (
        _m("android/view/SurfaceView", "getHolder", "()Landroid/view/SurfaceHolder;"),
        _m("android/view/SurfaceHolder", "addCallback", "(Landroid/view/SurfaceHolder$Callback;)V"),
        _m("android/view/SurfaceHolder", "removeCallback", "(Landroid/view/SurfaceHolder$Callback;)V"),
        _m("android/view/SurfaceHolder", "getSurface", "()Landroid/view/Surface;"),
    ), (), ((_m("android/view/SurfaceHolder", "addCallback", "(Landroid/view/SurfaceHolder$Callback;)V"),
             _m("android/view/SurfaceHolder", "removeCallback", "(Landroid/view/SurfaceHolder$Callback;)V")),)),
    AndroidCapability("audio-track-java", (
        _m("android/media/AudioTrack", "getMinBufferSize", "(III)I", True),
        _m("android/media/AudioTrack", "play", "()V"),
        _m("android/media/AudioTrack", "write", "([BII)I"),
        _m("android/media/AudioTrack", "stop", "()V"),
        _m("android/media/AudioTrack", "release", "()V"),
    ), min_api=3),
    AndroidCapability("audio-record-java", (
        _m("android/media/AudioRecord", "<init>", "(IIIII)V"),
        _m("android/media/AudioRecord", "startRecording", "()V"),
        _m("android/media/AudioRecord", "read", "([BII)I"),
        _m("android/media/AudioRecord", "stop", "()V"),
        _m("android/media/AudioRecord", "release", "()V"),
    ), (PermissionRule(_P + "RECORD_AUDIO"),), ((_m("android/media/AudioRecord", "<init>", "(IIIII)V"), _m("android/media/AudioRecord", "release", "()V")),)),
    AndroidCapability("audio-focus", (
        _m("android/media/AudioManager", "requestAudioFocus", "(Landroid/media/AudioFocusRequest;)I"),
        _m("android/media/AudioManager", "abandonAudioFocusRequest", "(Landroid/media/AudioFocusRequest;)I"),
    ), (), ((_m("android/media/AudioManager", "requestAudioFocus", "(Landroid/media/AudioFocusRequest;)I"),
             _m("android/media/AudioManager", "abandonAudioFocusRequest", "(Landroid/media/AudioFocusRequest;)I")),), min_api=26),
    AndroidCapability("touch-input", (
        _m("android/view/MotionEvent", "getActionMasked", "()I"),
        _m("android/view/MotionEvent", "getActionIndex", "()I"),
        _m("android/view/MotionEvent", "getPointerCount", "()I"),
        _m("android/view/MotionEvent", "getPointerId", "(I)I"),
        _m("android/view/MotionEvent", "getX", "(I)F"),
        _m("android/view/MotionEvent", "getY", "(I)F"),
        _m("android/view/MotionEvent", "getEventTime", "()J"),
        _m("android/view/MotionEvent", "getAxisValue", "(I)F"),
        _m("android/view/MotionEvent", "getSource", "()I"),
    )),
    AndroidCapability("key-input", (
        _m("android/view/KeyEvent", "getAction", "()I"),
        _m("android/view/KeyEvent", "getKeyCode", "()I"),
        _m("android/view/KeyEvent", "getRepeatCount", "()I"),
        _m("android/view/KeyEvent", "getMetaState", "()I"),
        _m("android/view/KeyEvent", "getEventTime", "()J"),
    )),
)

# Abstract methods the platform calls on each callback type.  A managed class that extends or
# implements one must implement all of them (ART throws AbstractMethodError otherwise).
CALLBACK_ABSTRACT_METHODS: dict[str, tuple[tuple[str, str], ...]] = {
    "Landroid/view/SurfaceHolder$Callback;": (
        ("surfaceCreated", "(Landroid/view/SurfaceHolder;)V"),
        ("surfaceChanged", "(Landroid/view/SurfaceHolder;III)V"),
        ("surfaceDestroyed", "(Landroid/view/SurfaceHolder;)V"),
    ),
    "Landroid/view/View$OnTouchListener;": (("onTouch", "(Landroid/view/View;Landroid/view/MotionEvent;)Z"),),
    "Landroid/view/View$OnKeyListener;": (("onKey", "(Landroid/view/View;ILandroid/view/KeyEvent;)Z"),),
    "Landroid/view/View$OnGenericMotionListener;": (("onGenericMotion", "(Landroid/view/View;Landroid/view/MotionEvent;)Z"),),
    "Landroid/net/wifi/p2p/WifiP2pManager$ActionListener;": (("onSuccess", "()V"), ("onFailure", "(I)V")),
    "Landroid/net/wifi/p2p/WifiP2pManager$ChannelListener;": (("onChannelDisconnected", "()V"),),
    "Landroid/net/wifi/p2p/WifiP2pManager$GroupInfoListener;": (("onGroupInfoAvailable", "(Landroid/net/wifi/p2p/WifiP2pGroup;)V"),),
    "Landroid/media/MediaCodec$Callback;": (
        ("onInputBufferAvailable", "(Landroid/media/MediaCodec;I)V"),
        ("onOutputBufferAvailable", "(Landroid/media/MediaCodec;ILandroid/media/MediaCodec$BufferInfo;)V"),
        ("onError", "(Landroid/media/MediaCodec;Landroid/media/MediaCodec$CodecException;)V"),
        ("onOutputFormatChanged", "(Landroid/media/MediaCodec;Landroid/media/MediaFormat;)V"),
    ),
    "Landroid/media/AudioManager$OnAudioFocusChangeListener;": (("onAudioFocusChange", "(I)V"),),
    "Landroid/content/BroadcastReceiver;": (("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"),),
    "Landroid/app/Service;": (("onBind", "(Landroid/content/Intent;)Landroid/os/IBinder;"),),
    "Ljava/lang/Runnable;": (("run", "()V"),),
    "Landroid/os/Handler$Callback;": (("handleMessage", "(Landroid/os/Message;)Z"),),
}

# Lifecycle overrides whose framework implementation must run (``call_super``): ART throws
# SuperNotCalledException when an Activity/Service override skips it.
SUPER_REQUIRED: dict[str, frozenset[tuple[str, str]]] = {
    "Landroid/app/Activity;": frozenset({
        ("onCreate", "(Landroid/os/Bundle;)V"), ("onStart", "()V"), ("onResume", "()V"), ("onPause", "()V"),
        ("onStop", "()V"), ("onDestroy", "()V"), ("onRestart", "()V"),
    }),
}

COMPONENT_SUPERCLASSES = {"service": "Landroid/app/Service;", "receiver": "Landroid/content/BroadcastReceiver;"}

def _ndk_permission_index() -> dict[bytes, tuple[str, tuple[PermissionRule, ...]]]:
    """Symbol CID -> (capability, permission rules) for the NDK and POSIX contracts above."""
    from xax_platform import posix_android_api, posix_async_api

    index: dict[bytes, tuple[str, tuple[PermissionRule, ...]]] = {}
    for symbol in aaudio_api(AAUDIO_INPUT).symbols:
        index[symbol.cid] = ("aaudio-input", (PermissionRule(_P + "RECORD_AUDIO"),))
    internet = (PermissionRule(_P + "INTERNET"),)
    base = posix_android_api()
    for symbol in (base.socket, base.connect, posix_async_api(base).socket, posix_async_api(base).accept4):
        index[symbol.cid] = ("posix-sockets", internet)
    return index


def capability_for_member(owner: str, name: str, descriptor: str) -> AndroidCapability | None:
    for capability in CAPABILITIES:
        for member in capability.members:
            if (member.owner, member.name, member.descriptor) == (owner, name, descriptor):
                return capability
    return None


def _decode_method_identity(identity: bytes) -> tuple[str, str, str] | None:
    """(owner, name, descriptor) of a typed JNI method-ID identity (xax_jni._typed_member_identity)."""
    for prefix in (b"android.jni.jmethodID/v1/", b"android.jni.jmethodID/v2/"):
        if identity.startswith(prefix):
            from xax_compiler import Cursor

            cursor = Cursor(identity[len(prefix) + 1:], "jmethodID")
            return tuple(cursor.byte_string().decode("utf-8") for _ in range(3))  # type: ignore[return-value]
    return None


def reachable_platform_uses(roots: tuple[bytes, ...], resolve: Callable[[bytes], SemanticObject]) -> tuple[set[tuple[str, str, str]], set[bytes]]:
    """Typed JNI methods (owner, name, descriptor) and object CIDs reachable from ``roots``."""
    from xax_compiler import _decode_opaque_identity_type

    seen: set[bytes] = set()
    pending = list(roots)
    methods: set[tuple[str, str, str]] = set()
    while pending:
        cid = pending.pop()
        if cid in seen:
            continue
        seen.add(cid)
        obj = resolve(cid)
        pending.extend(obj.references)
        if obj.kind == Kind.TYPE:
            try:
                identity = _decode_opaque_identity_type(obj)
            except Exception:  # noqa: BLE001 - not an opaque identity type
                continue
            member = _decode_method_identity(identity)
            if member is not None:
                methods.add(member)
    return methods, seen


def _required(rule: PermissionRule, min_sdk: int, target_sdk: int) -> bool:
    return target_sdk >= rule.from_target and (rule.device_max == 0 or min_sdk <= rule.device_max)


def platform_usage_violations(manifest, declarations, classes, roots, resolve) -> list[str]:
    """Every platform rule a managed APK breaks; ``declarations`` may be None."""
    from xax_manifest import AndroidPlatformDeclarations, platform_declaration_violations

    declarations = declarations or AndroidPlatformDeclarations()
    problems = list(platform_declaration_violations(manifest, declarations))
    declared = {item.name: item for item in declarations.permissions}

    def need(rules: tuple[PermissionRule, ...], why: str) -> None:
        for rule in rules:
            if not _required(rule, manifest.min_sdk, manifest.target_sdk):
                continue
            item = declared.get(rule.permission)
            if item is None:
                problems.append(f"{why}: needs {rule.permission}")
            elif item.max_sdk and (rule.device_max == 0 or item.max_sdk < rule.device_max):
                problems.append(f"{why}: {rule.permission} maxSdkVersion {item.max_sdk} does not cover the API levels that need it")

    methods, objects = reachable_platform_uses(roots, resolve)
    used_capabilities: set[str] = set()
    for owner, name, descriptor in sorted(methods):
        capability = capability_for_member(owner, name, descriptor)
        if capability is None:
            continue
        used_capabilities.add(capability.name)
        if manifest.min_sdk < capability.min_api:
            problems.append(f"{owner}.{name}{descriptor}: needs API {capability.min_api}, minSdk is {manifest.min_sdk}")
    for capability in CAPABILITIES:
        if capability.name in used_capabilities:
            need(capability.permissions, capability.name)
            for acquire, release in capability.releases:
                if (acquire.owner, acquire.name, acquire.descriptor) in methods and (release.owner, release.name, release.descriptor) not in methods:
                    problems.append(f"{capability.name}: {acquire.owner}.{acquire.name} is acquired but {release.owner}.{release.name} is never reachable")
    for cid, (name, rules) in sorted(_ndk_permission_index().items()):
        if cid in objects:
            need(rules, name)
    by_descriptor = {item.class_descriptor: item for item in classes.values()}
    for item in classes.values():
        implemented = {(method.name, method.descriptor) for method in item.methods}
        for parent in (item.superclass_descriptor, *item.interfaces):
            for name, descriptor in CALLBACK_ABSTRACT_METHODS.get(parent, ()):
                if (name, descriptor) not in implemented:
                    problems.append(f"{item.class_descriptor}: {parent} requires {name}{descriptor}")
        for method in item.methods:
            if (method.name, method.descriptor) in SUPER_REQUIRED.get(item.superclass_descriptor, frozenset()) and not method.call_super:
                problems.append(f"{item.class_descriptor}.{method.name}: the framework override must call super")
    for component in declarations.components:
        managed = by_descriptor.get("L" + component.class_name.replace(".", "/") + ";")
        if managed is None:
            problems.append(f"{component.class_name}: declared {component.kind} is not a managed class in this APK")
        elif managed.superclass_descriptor != COMPONENT_SUPERCLASSES[component.kind]:
            problems.append(f"{component.class_name}: a {component.kind} must extend {COMPONENT_SUPERCLASSES[component.kind]}")
    return problems


def check_managed_platform_usage(reader, manifest, declarations_carrier, classes, exports) -> None:
    """Build-time gate for a managed APK: fail with every platform-rule violation at once."""
    from xax_manifest import decode_android_platform_declarations

    declarations = decode_android_platform_declarations(declarations_carrier) if declarations_carrier is not None else None
    roots = tuple(view.function_cid for view in exports.values())
    problems = platform_usage_violations(manifest, declarations, classes, roots, reader.get)
    if problems:
        where = declarations_carrier.cid.hex() if declarations_carrier is not None else "managed-apk"
        fail("XAX.BUILD.ANDROID", where, "ANDROID-PLATFORM-RULES", "no platform-rule violations", problems)
