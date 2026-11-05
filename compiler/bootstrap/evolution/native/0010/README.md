# Ledger 0010: OI-52 R1, x86-64 checked bounds past imm32 (ADR-373)

Three batch records (`../../0010-x86-64-wide-checked-bounds*.batch`: the general driver, the request store, the x86-64
general program) redefine the register path's checked access, `em_memory` (F638 in the driver and the request, F140
in the general program; the same function object in all three). They were written from its native view with
`em_memory.awk`:

    awk -v EB=<eb's handle> -v LASTB=297 -v LASTP=8503 -v LASTN=5034 -f em_memory.awk <view of em_memory>

The awk script appends new blocks after the last block, so no existing handle is renumbered. It raises the reject's
threshold to 2^64 - 1 and sends B87 into the new blocks. Those blocks take a bound below 2^31 to the old imm32 compare
(B91). A larger bound goes through three `eb` calls, `movabs r11, bound` then `cmp index, r11`, to the trap jump
(B94). Heap views and memory pass through block parameters; plain values may cross blocks.
