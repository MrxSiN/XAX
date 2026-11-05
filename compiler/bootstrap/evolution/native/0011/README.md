# Ledger 0011: OI-52 R1 on the frame path (ADR-374)

The batches `../../0011-x86-64-wide-checked-bounds-frame*.batch` redefine `fr_memory` and `fr_tail` (F986, F1005 in the
driver and the request; F219, F225 in the x86-64 general program) from their native views with
`awk -v EB=<eb's handle> -f frame_r1.awk <view>`. The script finds each checked bound's reject threshold, then the
`cmp reg, imm32` emission after it (`eb(word, 3)` and `eb(bound, 4)`) and the block where that emission rejoins.
It appends blocks that take a bound of 2^31 or more through `movabs r11, bound; cmp reg, r11` to the rejoin block, with
the register read from the old opcode word. It checks each assumption and stops on any other shape.
