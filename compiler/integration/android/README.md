# Android arm64-v8a integration fixture

`libxposed_fixture` packages the XAX-generated `libxaxmodule.so` directly from
`app/src/main/jniLibs/arm64-v8a/`. Gradle does not compile the library with
CMake or ndk-build.

Modern libxposed metadata is under `app/src/main/resources/META-INF/xposed/`.
The fixture intentionally has no legacy `assets/xposed_init` or
`assets/native_init` entry. It is a native-library packaging and `dlopen` oracle,
not a loadable module: it has no Java entry, and libxposed API 102 frameworks such
as Vector ignore an APK without `java_init.list` and never open native entries on
their own (ADR-178). The Vector-loadable native module is the directly emitted
`compiler/benchmarks/android_libxposed_native_fixture.apk`.

`validate_on_device.sh` is an integration oracle for a connected arm64 Android
device/emulator. It needs `adb` and `ANDROID_NDK_HOME`; the C loader exists only
to call Android `dlopen`/`dlsym` during validation and is not part of the XAX
compiler or generated module.

## Direct Activity APK runtime validation

`validate_activity_apk.sh` is the validation-only runtime oracle for the directly
emitted signed APK at `compiler/benchmarks/android_minimal_activity.apk`. It does
not build or modify the APK and has no Gradle/NDK dependency. On a connected
arm64 Android device/emulator it:

1. installs the directly emitted v2-signed APK;
2. launches `xax.generated.XaxActivity` and requires `Status: ok`;
3. verifies the process survives the lifecycle JNI callback;
4. dumps the accessibility hierarchy and requires initial button text `XAX`;
5. taps the center of the full-screen `setContentView(View)` button;
6. verifies the process survives the click JNI callback; and
7. requires the visible text to become `Clicked`.

Set `XAX_ANDROID_APK=/path/to.apk` to validate another emitted artifact. Set
`XAX_KEEP_INSTALLED=1` to leave the package installed after validation.

This script requires `adb` and an arm64-v8a Android target. It is validation-only
and does not make Android runtime claims until its output is actually recorded.

## Vector runtime harness (libxposed API 102)

The automated framework oracle is `vector/` (see `vector/README.md`): it pins
Vector v2.2 and the libxposed API/service revisions it builds against, installs
signed XAX profiles on a rooted device running Vector, enables and scopes them
through Vector's CLI, and records 27 runtime checks in
`compiler/benchmarks/android_vector_runtime_evidence.json`. That file is the
UNEXECUTED plan until the harness runs on such a device.

## Modern libxposed API-102 controlled runtime pair (manual oracle)

The automated harness above supersedes this script for Vector; it remains a
framework-neutral manual check.

`validate_libxposed_combined.sh` is the validation-only oracle for the paired
controlled target and generated modern-libxposed module. The repository emits
and test-signs two deterministic installable inputs:

- `compiler/benchmarks/android_libxposed_runtime_target_signed.apk`
  (`com.example.target`), whose `hookTarget(String):String` returns its input and
  initially displays `OriginalArg`;
- `compiler/benchmarks/android_libxposed_runtime_module_signed.apk`
  (`com.example.module`), scoped semantically to `com.example.target`, whose
  API-102 Hooker replaces argument 0, proceeds exactly once, captures the
  original result, and returns `HookedResult`.

Framework module enablement/scope configuration is not automated here: that
operation belongs to the installed framework's manager and is not a portable
Android platform API (the Vector harness uses Vector's own CLI for it). After installing/enabling the module and scoping
it to `com.example.target`, set `XAX_LIBXPOSED_PREPARED=1` and run the script.
It installs/replaces both APKs, launches the target Activity, checks process
survival, and requires visible text `HookedResult`. If `OriginalArg` is visible,
the script reports the module as inactive/unscoped instead of treating that as a
compiler success.

The script does not build, sign, enable, or widen scope for the module. Its
existence is reproducible validation infrastructure only; runtime success is not
claimed until output from an actual compatible Android/libxposed environment is
recorded.

## File/thread/socket XAX contract runtime validation

`validate_platform_contracts.sh` is the execution oracle for the platform-library
contracts. It builds an `android-arm64-v8a-shared-v4` XAX shared object whose
exported functions themselves call `open/write/close`, `pthread_create/join`,
and `socket/connect/send/recv/close`. A tiny validation-only C process supplies
raw buffers, a thread callback, and a loopback TCP peer; it is not linked into
the XAX artifact.

The script requires `adb`, `ANDROID_NDK_HOME`, and an arm64-v8a Android device or
emulator. Success is recorded only after the device process prints
`XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1`; the evidence JSON remains
explicitly `executed: false` on hosts where that environment is unavailable.

## Counter app against its Java + NDK twin (R4 harness)

`python -m benchmarks.bench_android_counter_twin --device` (from `compiler/`, with
`ANDROID_NDK_HOME`, `ANDROID_BUILD_TOOLS`, and `ANDROID_JAR` as for
`bench_android_ndk_twin.py`) builds the twin in `benchmarks/android_counter_twin/`,
installs each app in turn (they share the package `xax.counter`), checks its
click path, and records cold-start `TotalTime` and total PSS over alternating
install-once passes (`XAX_TWIN_WARMUP`, default 3; `XAX_TWIN_RUNS`, default 16).
The result counts as performance and memory evidence only when the target is
arm64 hardware (`hardware: true`); an emulator run only shows that the harness works.

## Running the oracles without a device: x86_64 emulator with ARM translation

The oracles need an `adb` target that advertises `arm64-v8a`. Without a device,
an x86_64 `google_apis` system image with built-in ARM translation
(`ro.dalvik.vm.native.bridge=libndk_translation.so`) runs the arm64 libraries:
API 30 and API 32 have it (fingerprints `…_x86_64_arm64`); the AOSP `default`
images and the API 33 `google_apis` image do not, and the emulator refuses arm64
images on x86_64 hosts. A run on such an image is correctness evidence only: the
XAX library executes under binary translation, not on arm64 hardware, so it is
never performance or memory evidence (`XAX_SPEC.md` §21.2, OI-44).

```bash
sdkmanager "platform-tools" "emulator" "system-images;android-32;google_apis;x86_64"
# AVD config.ini: abi.type=x86_64, image.sysdir.1=system-images/android-32/google_apis/x86_64/
emulator -avd <name> -no-window -no-audio -no-snapshot -no-boot-anim -no-metrics \
    -gpu swiftshader_indirect -memory 3072 -cores 4 [-accel off]
```

With hardware virtualization (`/dev/kvm`) this is an ordinary emulator. Without
it (`-accel off`, software emulation) the framework is so slow that its own
timeouts fire. What worked on such a host:

- **API 32, with `ro.hw_timeout_multiplier`.** Android 12 and later scale their
  framework timeouts by it; Android 11 (API 30) does not, and there an arm64 app
  never attaches within the fixed 10-second limit. After boot, as root:
  `setprop ro.hw_timeout_multiplier 20`, then `stop; start` so `system_server`
  rereads it. (The emulator's `-prop` option did not set it.)
- **A debugger attached to `system_server`** during boot: Android's watchdog does
  not kill a process that is being debugged. A bare JDWP handshake through
  `adb forward tcp:<port> jdwp:<pid>` is enough; `jdb` is not, because it suspends
  the VM on uncaught exceptions.
- **No ANR dialogs:** `settings put global hide_error_dialogs 1` and
  `anr_show_background` left at 0; ANR dialogs of system apps otherwise take the
  focus, and `uiautomator` then finds no window to dump.
- **No framework crash when the network stack is killed:** under load its process
  misses ANR deadlines and is killed, and `system_server` then crashes on purpose
  ("Lost network stack"). `device_config put connectivity min_uptime_before_crash
  999999999999` keeps `system_server` up while the stack restarts.
- **Wait for the launcher** after every framework start: until the user is
  unlocked, an installed app's activities do not resolve ("Activity class … does
  not exist").
- **Generous oracle timeouts:** `XAX_UI_TIMEOUT=900 XAX_TAP_RETRY=240` for
  `validate_counter_apk.sh` (a launch takes about a minute and one UI dump about
  half a minute under software emulation, and a tap is occasionally lost).
- The `wrap.<package>` property lengthens the attach limit too, but starts the
  process without ARM translation, so the arm64 library cannot load. Disabling
  persistent telephony or Bluetooth packages to save CPU makes them crash in a
  loop; leave them enabled.
