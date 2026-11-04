"""S15e.5 (ADR-327): ``xax_jvm._compile_method``'s driver as XAX functions: the two passes (the first counts each
value's reads in a throwaway pool; the second keeps a value read once on the operand stack), the retry that keeps
parameters a zero store would have to initialize, and per pass the analyses, the definite assignment, the zero
stores, the layout (fallthrough chains, jump threading), every block (its nodes, its terminator with the edges'
parallel copies, tail merging of equal return blocks), the trap, the line table, the fixups, the frames and the
operand stack's depth.  The method's result goes to the class's method store (``xax_selfhost_jvm``).
"""

from __future__ import annotations

from xax_selfhost_jvm_code import kind

WORK_WORDS = (1 << 21) + 5 * (1 << 18)  # the effective/reachability worklist, then the task stack


# -- edge copies ---------------------------------------------------------------------------------------------------------


# -- definite assignment ---------------------------------------------------------------------------------------------------


# -- layout ---------------------------------------------------------------------------------------------------------------


# -- blocks ---------------------------------------------------------------------------------------------------------------


