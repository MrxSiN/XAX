# A Vulkan host in XAX: a SPIR-V kernel on GPU hardware (`gpu-spirv-cuda-metal-dxil`)

`../vulkan_gpu_evidence.json` is the record. Everything here is a native batch (`docs/09_AI_PROTOCOL.md` section 16)
applied with the Windows seed `../../bootstrap/windows/xaxc-windows-x86_64.exe`; no Python, shell or C is in this
directory.

- `hash_records.batch`: the kernel. A batch on `kernel_base_request.xax` that defines a record-fingerprint function
  (16384 records of 16 words, one invocation per record, rotate/multiply mixing) and replaces the base kernel `F0`
  with it. The SPIR-V target, entry contract and bindings are the production `spirv-vulkan-compute-v1` profile.
- `kernel_base_request.xax`: the collatz kernel's SPIR-V build request (2,662 bytes). It was made with the Python
  reference constructors (`benchmarks.spirv_kernels.collatz_kernel`, `build_request`) because the native edit
  interface cannot give a request a non-Windows target (`replace` takes a function). Only its target, package and
  profile are used.
- `vkhost.batch`: the host. A batch on `../../integration/windows_helpers/hash_request.xax` (root `7afd44ec...`) that
  supplies 29 `vulkan-1.dll` declarations, `RtlMoveMemory`, two `VirtualFree` forms and a `WriteFile` form as
  objects (`win64-c`; handles, sizes and struct addresses are `bits64`/`bits32`, structs are built with checked
  stores into one 1.1 MiB view, addresses come from `pointer_address`), and replaces the BLAKE3 host's entry `F1`.
  It reads the SPIR-V module from standard input, generates the input words (LCG, `x = x * 1664525 + 1013904223`
  from 12345), selects physical device index 0, runs the dispatch and writes 67,584 bytes to standard output:
  `VkPhysicalDeviceProperties` (824 bytes), the kernel's trap-status word at offset 0x400 and the 16384 result
  words at 0x800. The exit status is the OR of every `VkResult` (2 to 6: a checked step failed).
- `vkhost_device1.batch`: two `const` edits of the host store (`N81` and `N87`): device index 1.

## Run (Windows 11, PowerShell, from this directory)

```text
$x = ..\..\bootstrap\windows\xaxc-windows-x86_64.exe
& $x edit kernel_base_request.xax hash_records.batch k.xax ; & $x verify k.xax k.diag
& $x resolve k.xax ks.xax ; & $x build ks.xax hash.spv k.prov              # 3,784 bytes
& $x edit ..\..\integration\windows_helpers\hash_request.xax vkhost.batch h.xax ; & $x verify h.xax h.diag
& $x resolve h.xax hs.xax ; & $x build hs.xax vkhost0.exe h.prov           # 6,656 bytes, device index 0
& $x edit h.xax vkhost_device1.batch h1.xax ; & $x resolve h1.xax h1s.xax ; & $x build h1s.xax vkhost1.exe h1.prov
Start-Process .\vkhost0.exe -RedirectStandardInput hash.spv -RedirectStandardOutput out0.bin -Wait -NoNewWindow
```

Use `Start-Process` redirection: with `cmd /c "x.exe < f > g"` the existing BLAKE3 host also fails here (exit -1).

## Check

The results at 0x800 must equal this CPU computation (32-bit wrap; `rotr` is rotate right):

```text
x = 12345 ; word[j] = (x = x * 1664525 + 1013904223)             for j in 0 .. 262143
h = 0x811C9DC5 ; for w in word[16r .. 16r+15]: h = rotr(h ^ w, 13) * 0x85EBCA6B + 0xC2B2AE35
out[r] = (h ^= rotr(h, 16) ; h *= 0x27D4EB2F ; h ^ rotr(h, 15))   for r in 0 .. 16383
```

The SHA-256 of the 65,536 result bytes is `1b7baa11...604fe` (`../vulkan_gpu_evidence.json`). On 2026-11-13 both the
RTX 3060 Laptop GPU (index 1) and the AMD Radeon iGPU (index 0) matched it, 3 runs each. A one-constant native edit
of the kernel (`const N11 3266489910`) makes 16383 records differ, so the check can fail.
