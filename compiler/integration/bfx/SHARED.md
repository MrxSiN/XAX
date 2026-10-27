# BFX decisions as Android shared libraries

[shared_arm64.xax](shared_arm64.xax) is a canonical host for the Android integer target
(`android-arm64-v8a-shared-v5`). Its one export, `bfc_call_v1`, calls an empty decision: the
same empty decision object as [standalone_arm64.xax](standalone_arm64.xax). A `bbc bind
android-arm64` record therefore binds it once its expected root and the graph owning the decision
reference are retargeted. There is no loader, libc, interpreter or BFX parser in the library.

Root: `ffd141c47487642b66a2ab9c8be02f217363ae5c0bb81106f04a6e8e6750be84`.
Store SHA-256: `d77b35172d73ac34792669a608efbaabc6938b04bf0650ff28e692747b792d17` (12,191 bytes).
It was made once with the generic graph builder; later changes use workspace transactions.

## ABI

```text
uint64_t bfc_call_v1(const uint8_t *in, uint64_t in_len, uint8_t *out, uint64_t out_cap,
                     uint8_t *tape, uint64_t tape_len, uint64_t budget, uint64_t *out_len);
```

| Status | Meaning |
|---:|---|
| 0 | Success; `*out_len` bytes of output |
| 2 | Output capacity exhausted |
| 3 | Tape movement out of bounds, or the call was rejected |

The call rejects with 3 and touches no buffer unless `tape_len >= 65536`, `in_len <= 65536` and
`out_cap <= 65536`. Otherwise the decision reads only `in[0, in_len)` (then zeros), writes only
`out[0, out_cap)`, zeroes and uses `tape[0, 65536)`, and `*out_len` is stored after it returns.
The caller provides those extents; a C pointer proves none of them. BBC has no instruction
budget, so `budget` is ignored and nonterminating programs do not return.

## Build

From `compiler/src`, with a record from `bbc.exe bind android-arm64 [-O0|-O1] < program.bf`:

```text
python -m xax_android_bfc program.edit libprogram.so
```

`xax_android_bfc.bind` retargets the record and applies it with the reference transaction
applier, then verifies; `build` lowers the bound host with `compile_android_shared`. This is a
generic-SDK step; a native `bbc compile` shared-library target is not implemented.

## Executed evidence (2026-10-27)

On a Pixel 8 Pro (Android 17/API 37), the nine YouTubeHideAds 1.2.1 policy programs
(whole-line `#` annotations removed, BBC `129995200d54`, O1) were compared with the libraries
shipped in that release, built by the earlier BrainfuckCC compiler. A driver outside every
repository called both on the same inputs: exhaustive Boolean inputs up to 16 bytes plus 200,000
random inputs per program, about 1.8 million calls. Old calls got a fresh 4,096-cell tape, BBC
calls a dirty 65,536-cell tape. Status, output length, output bytes and a 16-byte guard past the
output all matched, with no case skipped. Each library also rejected a 4,096-byte tape with status
3 without writing `*out_len` or the output.
