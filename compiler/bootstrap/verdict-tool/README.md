# The runtime verdict as an XAX program (ADR-207, ADR-430)

`xax_verdict` recomputes a runtime evidence file's R4 verdict from its raw `wall_seconds_samples`, twice: under
ADR-207 alone, as `xax_replacement.recompute_runtime_verdict` does today, and under ADR-430 (the null arm, the derived
role, and the leadership or parity verdict). It is the native rewrite ADR-430's Consequences call for. The matrix
check does not call it yet, so ADR-207 in `xax_replacement.py` still decides every level.

```text
xax_verdict <evidence.json> <out>
```

`<out>` gets two lines:

```text
adr207 pass <XAX arm> leads <fastest non-XAX arm>      or   adr207 fail <reason>
adr430 role <derived> declared <declared> pass ...     or   adr430 [role ... declared ...] fail <reason>
```

Exit status: 0 when `<out>` was written (whatever the verdicts); 2 unless there are exactly two arguments; 3 when a
file cannot be read or written, an argument is 4 KiB or longer, or the evidence is 8 MiB or larger.

## What it decides

- **Common checks** (both lines): `results` is an object, `host` is an object, and every arm whose value is an
  object has a `wall_seconds_samples` list of at least 5 numbers.
- **ADR-207**: an arm is XAX when its name starts with `xax`; every other arm, `null` included, is a baseline. There
  must be an XAX arm and two baselines, and the baselines meet the 15.0/15.0a policy (`javac` needs `kotlinc`;
  otherwise a C-family arm, by lowercase prefix `gcc`, `clang`, `msvc`, `c-`, `cpp` or `c++`, and one outside it).
  The XAX arm with the smallest median must be at most 0.9999x the fastest baseline's median and significantly
  faster (one-sided Mann–Whitney, p < 0.05). Ties in medians go to the bytewise smaller name.
- **ADR-430**: the arm named `null` is the null arm and is not a baseline; the file must declare `role`. With `c` the
  fastest baseline, the derived role is leadership when median(c) − median(null) ≥ median(c) / 2 and the null arm is
  significantly faster than `c`; otherwise parity. A declared role the samples contradict fails. Leadership passes
  when one of the k XAX arms (k ≤ 4) is at most 0.9999x `c` and significantly faster at p < 0.05 / k (Holm's first
  step). Parity needs exactly one XAX arm and passes when no baseline is significantly faster than it.

The test is `faster_p_value`'s (normal approximation, tie correction, continuity correction toward the null)
decided in integers: with D = 2U − nm − 1, N = n + m and K = (N + 1)N(N − 1) − Σ(t³ − t), p < α exactly when
D > 0 and 3D²N(N − 1)·2^30 > Z·nm·K in 128-bit arithmetic, Z = round(z_α² · 2^30) for z_α the one-sided normal
critical value. Medians are kept doubled, so they are exact.

## Limits

- Samples are read as decimal fixed point in units of 10^-12 s, truncated, from at most 18 significant digits; two
  samples that differ only beyond that compare equal. A negative sample, `true`, `false`, `null`, a string or a
  nested value in a sample list makes that arm fail the common check.
- At most 32 arms of names under 80 bytes, 8,192 samples per arm, and an evidence file under 8 MiB. JSON string
  escapes are skipped, not decoded, so a key or arm name is compared as its raw bytes.
- It does not check published ratios (`time_ratio_vs_fastest`, `time_ratio_vs_fastest_competitor`) against the
  samples; `xax_replacement.py` still does.
- The boundary p = α is decided against Z rounded to 2^-30, so a z within about 10^-9 (relative) of z_α can differ
  from the floating-point result.

## How it was made

`verdict.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `../evolution/ledger-tool/seed.xax`; its result is
`xax_verdict.xax`, which `xaxc verify` accepts. Its first 145 lines are `../status-tool/status.batch`'s (the driver's
declarations and view types, its five host functions, `@put` and `@putw`); the rest defines the tool and replaces the
seed's main. `xax_verdict_windows.xax` is `sh ../windows/generator/generate.sh xax_verdict.xax xax_verdict_windows.xax`.
Change the tool by a further batch on `xax_verdict.xax`, then `xaxc verify`.

Checked on 2026-11-27 with the release 0043 seeds, EXECUTED:

- On Windows 11, for every file of `compiler/benchmarks/` with a `results` key (28 at the time), the ADR-207 line
  passes exactly when `recompute_runtime_verdict` returns no reason. The Linux build (run in WSL 2) writes the same
  bytes as the Windows build for all 34 files that contain `"results"`.
- On 900 generated files (3 seeds of 300; 5 to 90 samples per arm, with and without ties, about 13% with a p between
  0.02 and 0.1) both lines equal a reference computed with `faster_p_value` and the ADR texts: 0 mismatches.
- `android_counter_parity_pixel1_2026-11-27.json` gives `adr430 role parity declared parity pass`.
