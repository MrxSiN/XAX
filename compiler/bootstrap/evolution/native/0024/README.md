# Ledger 0024: signed compares below 32 bits in the x86-64 general backend (OI-55, ADR-393)

The backend keeps a `bits<N>` value zero-extended and compares with a 32-bit or 64-bit `cmp`, so for N < 32 the
predicates `slt`, `sle`, `sgt` and `sge` ignored the operand's sign bit. Both lowerings now shift the two operands
left by `32 - N` before the 32-bit compare. A zero-extended value has nothing above bit N - 1, so nothing is lost and
the signed order of the shifted values is the signed order of the operands. Compares of other kinds and widths are
lowered as before.

- **The register lowering's `em_compare`** (`compare.src`, `compare_splice.awk`; CID `fa9cbfb3…` before), which
  emits the flags of every compare of that path: a compare node's (`setcc` follows) and a fused one's (the branch
  follows). The two edges that led to its `test`/`cmp` with an immediate (B22) and to its `cmp` of two registers
  (B41) now go through an instance of the source each. It finds the compare node (node `pos` of the block being
  lowered, `E_BI`; for a fused compare, where `pos` is the block's node count, the node `R_FUSED` names), and when
  that node is an `int.compare` of these two operands with kind 7 or above (`slt`..`sge`) and the left operand's
  width (`T_RW`) is 1 to 31, it emits

  ```text
  mov r11d, right | mov r11d, imm32     r11 is the path's scratch register: no value lives in it
  shl r11d, 32 - N
  push r11
  mov r11d, left
  shl r11d, 32 - N
  cmp r11d, [rsp]
  lea rsp, [rsp + 8]                    lea leaves the flags alone
  ```

  and returns. Any other compare goes on to B22 or B41 unchanged. The operands' own registers are not written, the
  allocator is not asked for a register (the caller already holds an unbound result register), and the one scratch
  register is enough because the shifted right operand waits on the stack.
- **The frame path's integer node function** (`frame.src`, `frame_splice.awk`; CID `a4e4e43c…` before). Its compare
  loads both operands (rax, r10) and emits `cmp` from B458. The one edge into B458 now goes through a block that
  reads the kind and, when it is 7 or above and the operand width is below 32, emits `shl eax, 32 - N` and
  `shl r10d, 32 - N` (`C1 E0 n 41 C1 E2 n`, one call of the byte emitter). This is the reference's frame lowering
  since ADR-392.

`mkbatch.sh compare|frame <store> <batch>` lists the store, finds the function by its CID, views it, splices the
source in (through `../0020/ws64.awk`, `../0020/blockrenum.awk` and `../0015/renumber.awk`) and writes the batch.
Both functions are in the driver, the request and `xax_x86_64_general.xax`, so each store has two batches:
`-compare`, then `-frame` on its result.

Why the register path is corrected in place: making such a function ineligible (the reference's ADR-392 guard)
sends it to the frame path, and the frame path lowers only `win64-c` foreign calls. A Linux process entry that held,
or inlined, a narrow signed compare was then rejected (`NATIVE-FOREIGN-ABI`). The reference's guard is removed and
its `emit_compare` emits the same bytes.

A state triple (pointer, view, effect) travels through the new blocks as block parameters, as everywhere in these
functions: the verifier rejects a return whose effect came by another path than its pointer
(`HEAP-VIEW-RETURN-WHOLE`).

Not changed: the predicate tables already flip the sign bit at the operand width; a compare folded into a load
(`T_CL`) has 32 or 64 bits. The AArch64 backends do not use these functions and were not examined.

Ceiling: a narrow signed compare is 25 bytes (28 with an immediate) and one stack round trip. Widths 8 and 16
could use the sub-register `cmp`, and an immediate could be shifted at compile time, if such compares ever matter
for speed.

`narrow_signed_compare.xax` is the check as an XAX program (constructed 2026-11-12, verified; a Linux x86-64 process
with no input or output). Over 256 operand pairs and their complements at widths 5, 8, 16 and 24 it compares each
signed predicate on the narrow operands with the same predicate on the operands sign-extended to 64 bits by
arithmetic (`(zext(x) xor top) - top`), and exits 1 when any pair disagrees: a compare node of two values, with a
constant on either side, a compare fused into its branch, each of these in a five-parameter function (the frame
path), and a compare in the process entry. `xaxc build narrow_signed_compare.xax check provenance`, then `./check`:
status 0 with the compiler after this ledger entry, 1 with the seed before it (`a35fd59f…`). Its oracle is the same
compiler's 64-bit compare, not the reference executor; `probe.py` below has that comparison.

`probe.py <xaxc>|reference [widths]` (run from `compiler` with `PYTHONPATH=src:reference:.`) builds the programs the change was
checked with and compares their output with the reference executor: 128 of 240 differ with the seed before this
ledger entry, none with the compiler built from the changed stores.
