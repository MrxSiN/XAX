# Android arm64-v8a integration fixture

`libxposed_fixture` packages the XAX-generated `libxaxmodule.so` directly from
`app/src/main/jniLibs/arm64-v8a/`. Gradle does not compile the library with
CMake or ndk-build.

Modern libxposed metadata is under `app/src/main/resources/META-INF/xposed/`.
The fixture intentionally has no legacy `assets/xposed_init` or
`assets/native_init` entry.

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

## Modern libxposed API-102 controlled runtime pair

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

Framework module enablement/scope configuration is intentionally not automated:
that operation belongs to the installed libxposed/Xposed manager and is not a
portable Android platform API. After installing/enabling the module and scoping
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
