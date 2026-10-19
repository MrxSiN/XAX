# BFX Android application

`android_bfx.xax` is the canonical application source: the native decision
caller, JNI onCreate bridge, managed UI graph, managed-class lifecycle carrier,
manifest, package and build request. The fixed decision function was produced
by `import_bfx.xax` from BBC's `examples/decision.bf` BFX output. The saved
snapshot, not a Python builder or its initial construction carrier, is source.
All later changes require verified expected-root workspace transactions.

The package is **org.bbc.bfxdecision**, Activity **.DecisionActivity**. It
accepts integer Intent extras `flag` (default 0) and `capacity` (default 1).

| Inputs | Behavior |
|---|---|
| flag 0, capacity 1 | PERMIT label and visible sample row |
| flag 1 or 255, capacity 1..16 | BLOCK label and hidden row |
| capacity 0 | ERROR label and hidden row after output-capacity failure |
| flag outside 0..255 or capacity outside 0..16 | ERROR without calling the decision |

Native evaluation allocates three distinct initialized 65536-byte views,
invokes the compiled Brainfuck decision directly, accepts exactly one output
byte of 0 or 1, releases all three allocations and returns the UI mode. Each
valid decision call zeroes its tape. Nonzero status, unexpected output length
or unexpected byte fails closed. Allocation failure retains the existing
checked-null trap before memory access; it is not a recoverable UI error.

The platform shell is the existing `android-managed-class-v1` carrier:
`onCreate(Bundle)` calls its superclass then the XAX JNI bridge; `evaluate(II)I`
forwards to the XAX native evaluator. There is no hand-written DEX shell.
The bridge calls the compiled XAX UI graph's static Java entry through JNI.
Its NUL-terminated class/member/descriptor strings have explicit initialized
heap storage held live until the call finishes, then released. The one-entry
jvalue pack is explicit stack storage, with its owner and memory frontier
threaded through the bounded call and ended afterwards. The local class
reference is explicitly deleted. The borrowed allocation pointers provide
read-only C-string ABI values; their initialized view owners stay live in the
caller. No pointer cast adds permissions or changes an element/address space.

The managed XAX graph reads extras, calls the Activity evaluator, creates the
panel/label/row and sets text and visibility. Its generated JVM class is linked
as `org/bbc/bfxdecision/Ui` and translated by XAX's existing DEX backend.

## Generic build path

The application uses existing generic XAX tools unchanged:

1. `xax_build.build` lowers the snapshot's `apk` request to the native library,
   manifest and managed-class platform DEX.
2. `xax_jvm.compile_jvm_bound_target` lowers the snapshot's `ui` entry;
   `xax_dex_jvm.translate_class` links its generated class to
   `org/bbc/bfxdecision/Ui`, and `write_dex` emits that class.
3. `xax_apk.build_unsigned_apk` packages the platform DEX as `classes.dex`, UI
   DEX as `classes2.dex` and `lib/arm64-v8a/libxaxapp.so`.
4. The existing public test signing fixture signs development APKs. This is
   test signing, not a production key.

The final APK uses both generic lowerings and generic ZIP packaging; the
single `apk` build request alone does not include the separate UI DEX. The
linkage identities are recorded in [android_cases.json](android_cases.json).
No application-specific Python package builder remains in this repository.
The external driver recorded in evidence only invokes these generic tools
against the saved source. It does not construct application behavior, parse
BFX or generate decision graphs. Repeated builds from the saved source
produced byte-identical artifacts.

## Executed evidence and test source

Eight Activity cases passed on Pixel 8 Pro, Android 17/API 37, using
`C:\platform-tools\adb.exe`. Labels and sample-row visibility were checked
from UI hierarchies; permit, block and exhaustion screenshots were captured.
The APK is 35493 bytes, native library 17432 bytes, platform DEX 888 bytes and
UI DEX 1844 bytes. No OOM-injection device test is claimed in this iteration.

`backend_tests.xax` checks 36 narrow arithmetic cases plus a 128 KiB stack
allocation executed in a fresh Windows process. Its no-argument entry returns the number
of failed checks; the observed result was zero.
The native importer still passes the 393 static record cases, 89 emitted
native decision cases and three exact frontend rebuild generations. Static
records and expected device results are data, not source programs or skipped
Python test stubs.

Package metadata installs canonical BFX stores, data and documentation under
`share/xax/bfx`.

[Verification evidence](retirement_evidence.json) records source hashes, device
results and build dependencies. The generic verifier,
backends, APK utilities and signer remain unchanged legacy Python bootstrap
utilities. The importer also executes on Android; see
[importer verification](android_import_evidence.json). The app embeds the
compiled decision and does not embed the importer.
