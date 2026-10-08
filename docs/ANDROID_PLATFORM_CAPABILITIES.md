# Android Platform Capabilities

Status: 2026-10-08, after ADR-202 to ADR-205. This page tracks the Android surface that the AutoHead capability audit (2026-10-07) listed as partial or unsupported. The audit table is the AutoHead project's historical record; this page is XAX's current status for the same rows.

Labels follow the repository evidence rule. **STRUCTURAL** means canonical contracts, verifier rules and deterministic lowering are tested on the host, but nothing ran on a device. **EXECUTED** means device evidence exists. No row was upgraded to EXECUTED by this work, and no replacement level changed.

| Capability | Before | Now | What XAX provides | Still needed |
|---|---|---|---|---|
| Activity lifecycle | partial | STRUCTURAL (EXECUTED for onCreate/onResume/onPause, ADR-199) | Managed-class overrides; the build rejects `Activity` lifecycle overrides without `call_super` | Device run of destroy and surface recreation |
| Services | partial | STRUCTURAL | Declared Service components with `foregroundServiceType`; FGS permission rules; `startForeground`/`stopForeground`/notification members | Device run; Android background-start rules are runtime behaviour |
| Broadcast callbacks | insufficiently tested | STRUCTURAL | Declared receivers with intent actions; `BOOT_COMPLETED` needs `RECEIVE_BOOT_COMPLETED`; `onReceive` is required | Delivery on the chosen device |
| Permissions | unsupported | STRUCTURAL | `uses-permission` with `maxSdkVersion`/`neverForLocation`; `checkSelfPermission`, `requestPermissions`, `onRequestPermissionsResult` (managed callback); build rejects reachable members whose permissions are missing | Runtime grant/deny/revoke on a device |
| Network sockets | partial | STRUCTURAL | Owned socket descriptors (linear), `accept4`, `SOCK_NONBLOCK`, `poll` readiness with deadlines, `eventfd` cancellation, `SO_ERROR`, byte-count partial I/O; `INTERNET` enforced | Device run |
| TLS | unsupported | STRUCTURAL | `SSLContext`/`SSLEngine` members (wrap/unwrap/handshake status/delegated tasks/close) with `INTERNET`; direct buffers via `NewDirectByteBuffer` | Handshake evidence; exception paths |
| Bluetooth | unsupported | STRUCTURAL | Adapter, paired devices, discovery with target/device-level permission rules (`BLUETOOTH_CONNECT`/`SCAN` vs legacy) | Device run |
| RFCOMM | unsupported | STRUCTURAL | Client and server members, stream read/write, release pairs | Device run; path-exact release (OI-47) |
| Bluetooth SDP | unsupported | STRUCTURAL | `listenUsing[Insecure]RfcommWithServiceRecord` registers the SDP record; closing the server socket removes it | OEM behaviour on the device |
| Wi-Fi | unsupported | STRUCTURAL | Network callbacks/requests, `hasTransport`, `getNetworkHandle`; `NetworkCallback` is a managed superclass | Device run |
| Wi-Fi Direct | unsupported | STRUCTURAL | `initialize`/`createGroup`/`removeGroup`/`requestGroupInfo`/`Channel.close`, listener abstract methods, `NEARBY_WIFI_DEVICES` rules | Device run |
| Hotspot control | unsupported | STRUCTURAL (local-only only) | `startLocalOnlyHotspot`, reservation `close`, API 30 gate | Device run; arbitrary tethering is not an app capability |
| MediaCodec | unsupported | STRUCTURAL | NDK `AMediaCodec`/`AMediaFormat` with linear tokens (imports verified in the ELF); Java members and `MediaCodec.Callback` abstract methods | Bounds-proven input buffers (OI-47); decode loop on a device |
| Surface rendering | partial | STRUCTURAL | `SurfaceHolder.Callback` completeness; `ANativeWindow` from a Surface, borrowed by geometry calls, released once | NULL-window path (OI-47); device run |
| AudioTrack | unsupported | STRUCTURAL | AAudio output stream (write-only by type); Java AudioTrack members; audio focus pair | Device run |
| AudioRecord | unsupported | STRUCTURAL | AAudio input stream (read-only by type) and Java AudioRecord; both require `RECORD_AUDIO` | Device run with grant and denial |
| Touch input | unsupported | STRUCTURAL; `getX` float return EXECUTED under Unicorn (ADR-205) | Exact `float` JNI results: `getX`/`getY`/`getAxisValue`, pointers, action, time; `OnTouchListener` | Device run |
| Hardware keys | unsupported | STRUCTURAL (EXECUTED for `onKeyDown`, ADR-199) | `KeyEvent` action/code/repeat/meta/time; `OnKeyListener`; rotary through `getAxisValue` | Rotary device run |
| Persistent settings | partial | STRUCTURAL | `rename`/`fsync`/`unlink` for atomic replacement on top of owned descriptors and `fdatasync` | Versioned format and corruption handling are application semantics |
| Timers | partial | STRUCTURAL | `timerfd` deadlines with owned descriptors; `poll` timeouts; `eventfd` cancellation | Device run |
| Threads / concurrency | partial | STRUCTURAL | pthread mutex/condition contracts; JNI attach/detach contracts already exist | Device run of worker attach/shutdown |
| Manifest generation | partial | STRUCTURAL | Permissions, features, foreground types, components | Install on a device |
| Android SDK metadata import | insufficiently tested | unchanged | — | Imported member execution |
| JNI interoperability | partial | STRUCTURAL; float calls and typed-record packs EXECUTED under Unicorn (ADR-205) | Mixed narrow-integer, float and reference `jvalue[]` packs; float results and fields | ART run of a float call; conditional exception refinement |

Rows that were already supported (file I/O, APK resources, APK signing) are unchanged.

Sources: `compiler/src/xax_android_platform.py`, `compiler/src/xax_platform.py`, `compiler/src/xax_manifest.py`, `compiler/src/xax_jni.py`; tests in `compiler/tests/test_xax_android_platform.py` and `compiler/tests/test_xax_jni_float.py`; normative text in `XAX_SPEC.md` Appendix B and `docs/11_ABI_PLATFORM.md` §16.8.
