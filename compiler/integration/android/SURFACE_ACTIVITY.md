# Declarative Surface Activity (2026-10-07)

`xax_android_components.android_surface_activity_semantics` defines the general
`android-surface-activity-v1` identity-only target carrier: two canonical UTF-8
byte strings (Activity DEX descriptor and accessible content description).
`decode_android_surface_activity` validates kind, prefix, UTF-8, complete
consumption and canonical reconstruction. `lower_android_surface_activity`
generates DEX directly using the existing assembled-method emitter.

The only generated override calls Activity.onCreate, constructs one SurfaceView,
sets its accessible description, and calls setContentView. There is no handwritten
managed code, native bridge, library, background task, timer, codec or network.
The Android window owns the view and its Surface. No application consumer touches
the Surface. This is a **platform skeleton**, not video rendering or projection.
SurfaceHolder callbacks, consumer ownership and destruction synchronization must
be separately specified and tested before a codec can use the surface.

The ordinary `xax_build.build` APK path accepts this carrier with one matching
manifest and an exact empty, parameterless build-selector function. The selector
only satisfies the existing build-entry contract; it emits no runtime method.
Any other module member or nonempty selector rejects instead of silently losing
application logic. This bounded profile does not yet compose resources/services
or native exports. DEX 039 requires minSdk >= 28. Existing UI carriers and APK
bytes are unaffected. Signing uses the existing external signing capability and
provenance path. `tests/test_xax_android_surface.py` checks determinism, malformed
carriers, closure rejection and exact generated structure.

Runtime oracle: install the generated signed APK on an explicitly selected device;
require successful Activity start, a live process and a visible SurfaceView in the
accessibility hierarchy; force-stop/relaunch and repeat. Preserve APK/store hashes,
device API/ABI, command outcomes and hierarchy. Never infer MediaCodec capability
or Android Auto compatibility from this check.

Platform contract: <https://developer.android.com/reference/android/view/SurfaceView>
and <https://developer.android.com/reference/android/view/SurfaceHolder.Callback>.
