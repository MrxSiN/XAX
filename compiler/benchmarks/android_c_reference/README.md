# Android NDK C oracle fixtures

These tiny C sources are validation oracles only. They are **not** part of the
XAX production pipeline.

With an Android NDK installed, run:

```sh
ANDROID_NDK_HOME=/path/to/ndk ./compare_ndk.sh
```

The script builds optimized arm64-v8a references and records `llvm-readelf`
and `llvm-objdump` output for comparison with XAX-generated libraries. The XAX
compiler itself does not invoke Clang, LLVM, GCC, CMake, or ndk-build.
