# Vector runtime integration (ADR-178)

XAX's Android hook target has one runtime contract:

```
XAX -> generated libxposed API-102 module -> Vector -> ART
```

Generated modules link only the public `io.github.libxposed.api` classes; they never
name Vector (`org.matrix.vector.*`), LSPosed, or the legacy `de.robv.android.xposed`
API. [Vector](https://github.com/JingMatrix/Vector) supplies the API at runtime and is
the reference implementation XAX is tested against. Any framework implementing
libxposed API 102 the same way is expected to work, but only Vector is tested.

## Pinned revisions

`vector_runtime_pin.json` (regenerate with `pin_libxposed_api.py`) records:

| Component | Revision |
| --- | --- |
| Vector | release `v2.2`, tag object `8b8fa04dbd58f73bd5187fc6af02b65459b890cc`, commit `88f8e1faa8b4e7ce20aefabe9c295cd746ea038e` |
| libxposed-api (`xposed/libxposed`) | `39cac0845771547c9c67a3e3ce255af110a54a0e` = tag `102.0.0` (`45e7c5cf`) plus one documentation commit ("at least one Java entry must be provided") |
| libxposed-service (`services/libxposed`) | `3318940876192e29cf6ab07637e899e22a87ebf0` = tag `102.0.0` |
| API artifact | `io.github.libxposed:api:102.0.0` AAR, SHA-256 `423484a6e1807e7a423c4b88fcd8176d104318259d91791877fed88fe91479d0` |

The four API Java sources in that AAR are byte-identical to the commit Vector pins
(SHA-256 values in the pin). The member table in the pin is parsed from the AAR's
`classes.jar` with XAX's own class-file parser; `@SinceApi` marks exactly the
API-102 additions (`HookBuilder.setId`, `HookHandle.getId/replaceHook`,
`detach`, the hot-reload callbacks and parameters).

```bash
curl -sSfLO https://repo1.maven.org/maven2/io/github/libxposed/api/102.0.0/api-102.0.0.aar
python -I integration/android/vector/pin_libxposed_api.py --aar api-102.0.0.aar \
    [--api-checkout path/to/libxposed-api@39cac084]      # exit 0 when the pin is current
```

## Evidence layers

1. **Structural/codegen** - `tests/test_xax_vector_contract.py`: every module fixture
   passes `xax_vector.check_vector_module_apk` (Vector v2.2's discovery, loading,
   instantiation, hot-reload and `native_init` rules; every libxposed reference
   resolved against the pinned table with its exact descriptor; API-102 members
   force `minApiVersion=102`; no legacy, implementation, or bundled API classes).
2. **ART verification** - `benchmarks/bench_android_art_verify.py`.
3. **Stand-in behaviour** - `benchmarks/bench_android_art_execute.py` runs each module
   under real ART with a recording framework (`../art_libxposed_harness`). Fast and
   deterministic, but it is not Vector.
4. **Vector runtime** - `vector_harness.py`, below. Only this layer is evidence of
   framework behaviour. Its first hardware run (ADR-197) found a hot-reload register
   bug that layers 1-3 accepted.

## Device requirements

- arm64-v8a Android 8.1+ (Vector supports 8.1 to 17), physical or an emulator image
  that can be rooted (e.g. a `google_apis` image with rootAVD).
- Root: Magisk with Zygisk enabled, **or** KernelSU with a Zygisk implementation
  (ZygiskNext or ReZygisk).
- Vector v2.2 or newer installed through the root manager (module id `zygisk_vector`);
  reboot once after installing it.
- In-process checks need a debuggable target process. The harness targets declare
  `android:debuggable` (explicit `AndroidManifestSpec.debuggable`), so a user build works;
  `ro.debuggable=1` also works. Without either, those checks are `UNEXECUTED`.
- Host: `adb` and Python 3.11+.

## Running it

```bash
cd compiler
adb devices                                   # one device, or export ANDROID_SERIAL
integration/android/vector/validate_vector_runtime.sh --vector-zip Vector-v2.2-<build>-Release.zip
# or keep the signed inputs:
PYTHONPATH=src:.:.. python -m benchmarks.bench_android_vector_profiles --out /tmp/xax-vector
integration/android/vector/validate_vector_runtime.sh --apks /tmp/xax-vector
```

The harness writes `benchmarks/android_vector_runtime_evidence.json`. It uninstalls
and reinstalls `xax.generated`, `com.example.module` and `com.example.target`, enables
and scopes each module with Vector's CLI (`/data/adb/modules/zygisk_vector/cli`),
turns on Vector's verbose log, and seeds one remote file under
`/data/adb/lspd/modules/0/xax.generated/files/`. Use a test device.
`XAX_VECTOR_TIMEOUT` (seconds, default 90) scales every wait. With several devices
attached, set `ANDROID_SERIAL`. The harness uninstalls its three packages when it finishes.

### In-process oracle: heap dumps, not JDWP

On Pixel 8 Pro / Android 17 (API 37) with Vector v2.2, attaching JDWP to any
Vector-hosted process aborts ART: `Check failed: method_index < num_methods_
(method_index=65535)` in `Instrumentation::UpdateEntrypointsForDebuggable` while the agent
attaches. This happens even with a module that installs no hook; the same target without
a module attaches normally. The default `--oracle heap` therefore reads `am dumpheap`
output (in-process, no JVMTI agent) with `hprof.py`. It decides loaded classes, instances,
field values, the framework's hook record behind a `HookHandle`, and hot-reload
generations (classes are non-moving, so class ids are stable across dumps). Checks that
need a breakpoint or a call (package_callbacks, class_loader, intercepted, deopt_order,
manual_unhook, module_services, remote_preferences, remote_files, protective) stay
`UNEXECUTED` under it. `--oracle jdwp` keeps the JDWP route for builds where attaching works.

## Profiles and checks

`benchmarks/bench_android_vector_profiles.py` builds the signed inputs from the
existing fixture builders (`android_vector_profiles_evidence.json` pins their
hashes). Targets: `target-string.apk` (`hookTarget(String)` echoes `OriginalArg`) and
`target-zero.apk` (`hookTarget()` returns `Original`), both `com.example.target`.

| Check | Profile | Oracle |
| --- | --- | --- |
| discovery, scope | managed | `vector-cli modules ls` / `scope ls` |
| module_prop | managed | Vector logs `Loaded module xax.generated successfully` in the target |
| java_init, instantiated | managed | JDWP: `XaxModule` loaded; one live instance |
| package_callbacks | managed | JDWP (`am start -D`): `onPackageReady` hit once |
| native_init | native | Vector logs `Initialized native module`; `/proc/<pid>/maps` has `libxaxapp.so` |
| hook_installed, intercepted, class_loader | hook | JDWP: `XaxHooker` loaded; `intercept` hit on relaunch (heap: `XaxHooker` loaded) |
| pass_through | hook | Activity resumed, `OriginalArg` shown, process alive |
| result / argument / combined replacement | result / argument / combined | `Hooked` / `HookedArg` / `HookedResult` shown |
| deopt_order | deopt | JDWP (`am start -D`): `deoptimize()` before `hook()` |
| retained_handle, manual_unhook | unhook | JDWP: `xaxHookHandle` live; no interception after `xaxUnhook()` |
| module_services | services | JDWP: `xaxFrameworkName()` is `Vector`, version non-empty |
| remote_preferences | remote_preferences | JDWP: preferences non-null under `PROP_CAP_REMOTE`; absent keys return defaults |
| remote_files | remote_files | JDWP: the seeded file is listed and opens with its size |
| hot_reload_callbacks, saved_state, stable_hook_id, replace_hook | hot_reload | install the `versionCode` 2 generation: Vector auto hot reload; new generation holds the target ClassLoader and a handle with ID `xax.primary`; only the new `XaxHooker` intercepts (heap: the record behind the new handle holds the new `XaxHooker`) |
| stable_id_validation | hot_reload_id_mismatch | second generation uses ID `xax.other`: replacement skipped, old hooker still intercepts (heap: no new handle; the old record holds the old `XaxHooker`) |
| protective | protective | JDWP throws inside `intercept` before `proceed`: `OriginalArg` shown, process alive, hook still active afterwards |
| process_survives | all | `pidof` unchanged through each profile |

`package_callbacks` and `deopt_order` depend on Android's wait-for-debugger running
before the package-ready phase; if the callback has already run when the debugger
attaches, the check is `INCONCLUSIVE`, not passed.

## Vector behaviour this target depends on

- Vector discovers a module only through `META-INF/xposed/java_init.list` and loads
  it only with at least one Java entry; it never dlopens native entries itself. The
  generated `XposedModule` loads `libxaxapp.so` in `onModuleLoaded`, and Vector's
  `do_dlopen` hook then calls its `native_init` (suffix match on the
  `native_init.list` name).
- Entry classes are instantiated with their no-argument constructor and attached
  with `attachFramework`; modules must not bundle API classes.
- Hot reload is offered only to single-Java-entry modules, and `autoHotReload`
  fires only when the module's `versionCode` changes. The new generation does not
  get `onModuleLoaded` or package callbacks again, so the generated `onHotReloaded`
  is pure DEX and calls no native code.
- Saved state is rejected when its class was defined by the old module class
  loader; the generated state is the target app's `ClassLoader`, which is not.
- `targetApiVersion >= 101` selects the modern loader; `minApiVersion` is only
  shown by the manager, so XAX itself refuses API-102 members behind
  `minApiVersion=101`.
- Remote preference *values* are written by the module's own app through
  libxposed-service; generated modules do not include that service, so the harness
  checks capability and default reads only.
