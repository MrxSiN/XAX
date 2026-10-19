# BFX integration

**BFX — Ballsdeep Brainfuck XAX** is BBC's portable handoff to XAX. Modules
use magic `42 46 58`, binary version byte `01` and the `.bfx` extension.
BBC's Brainfuck frontend is in `D:\GitHub\Brainfuck_Ballsdeep_Compiler`.

- [Decoder](../compiler/integration/bfx/README.md): record validation and loop pairing; 393 native cases passed on Android and Windows.
- [Importer](../compiler/integration/bfx/IMPORT.md): canonical graph/store emission; 393 record checks on Android and Windows, 89 native decision calls and three frontend generations on each platform passed.
- [Android app](../compiler/integration/bfx/ANDROID.md): canonical JNI/UI/lifecycle source; eight Pixel 8 Pro Activity cases passed.
- [Verification evidence](../compiler/integration/bfx/android_import_evidence.json): source hashes, artifacts, device results and backend regressions.

The maintained implementation consists of canonical XAX stores. Generic Python
verifier, backend and packaging utilities remain bootstrap dependencies.
The importer and Brainfuck frontend execute on Android and Windows. Native
lowering runs through the Windows build host. General Android large-composite
returns remain a separate backend limitation; the importer uses a narrower
verified interface.
