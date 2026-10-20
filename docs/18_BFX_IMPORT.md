# BFX integration

**BFX — Ballsdeep Brainfuck XAX** is BBC's portable handoff to XAX. Modules
use magic `42 46 58`, explicit binary version and the `.bfx` extension.
The transparent frontend emits v1; the optional BF optimizer emits v2 with
[declared CLEAR operations](../compiler/integration/bfx/CLEAR.md). The importer
accepts both; the unchanged standalone decoder remains strict v1.
BBC's Brainfuck frontend is in `D:\GitHub\Ballsdeep_Brainfuck_Compiler`.

- [Decoder](../compiler/integration/bfx/README.md): record validation and loop pairing; 393 native cases passed on Android and Windows.
- [Importer](../compiler/integration/bfx/IMPORT.md): canonical graph/store emission; 393 record checks on Android and Windows, 89 native decision calls and three frontend generations on each platform passed.
- [Android app](../compiler/integration/bfx/ANDROID.md): canonical JNI/UI/lifecycle source; eight Pixel 8 Pro Activity cases passed.
- [Verification evidence](../compiler/integration/bfx/android_import_evidence.json): source hashes, artifacts, device results and backend regressions.
- [Eight-byte tape reset](../compiler/integration/bfx/WIDE_RESET.md): current importer transaction, full-tape equivalence checks, native-call A/B and fresh Android process comparisons; no competitor surpassed.
- [V2 CLEAR lowering](../compiler/integration/bfx/CLEAR.md): exact-root graph edits, strict v1 compatibility, 652 Android/Windows record comparisons, 6,048 full-buffer decision calls and three-generation component fixed points on both targets.
- [Standalone Android process](../compiler/integration/bfx/STANDALONE.md): canonical host and callee-binding transaction; process timing improves over the pinned Awib configuration on the twelve-source subset, while brainfry remains faster. No unrestricted sweep or build/RAM victory.
- [Standalone Windows process](../compiler/integration/bfx/WINDOWS_STANDALONE.md): canonical kernel32-only host, public hello binding, 23 native programs and 28 host checks; explicit generic bootstrap inlining configuration for the Win64 call-path limit.

The maintained implementation consists of canonical XAX stores. Generic Python
verifier, backend and packaging utilities remain bootstrap dependencies.
The importer and Brainfuck frontend execute on Android and Windows. Native
lowering runs through the Windows build host. General Android large-composite
returns remain a separate backend limitation; the importer uses a narrower
verified interface.
