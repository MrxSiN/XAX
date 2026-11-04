"""S15e.5 (ADR-327): the lowering of ``xax_jvm._compile_method_pass`` as XAX functions (stage S15e.5a).

``get``, ``put`` and ``lower_node`` call each other recursively in the bootstrap (an expression tree is lowered where
it is read; a short-circuit condition jumps through its operands).  Here they are tasks on an explicit stack
(``jl_run``): a task's expansion pushes its steps in reverse, and every condition that reads the deferred values is
evaluated when the task is reached, so the bytes and the pool entries come in the bootstrap's order.

Task kinds (``K_*``, five words each: kind and four arguments): ``GET`` a value; ``NODE`` lower a node; ``OP`` a few
constant bytes; ``ICONST``/``LCONST``; ``PUT`` a value; ``MASK`` (descriptor, width); ``CALL`` an internal method
(callee function); ``JAVA`` a fixed ``java.lang`` method or the shared ``xax$pk``; ``BRANCH`` (opcode, label);
``MARK`` (label); ``JUMP`` (condition, when, label); ``STORE`` (descriptor, slot); ``GETLONG`` (value, width, signed);
``FCONST`` (raw bits, width); ``FOREIGN`` (member record): a platform call's opcode and pool entry; ``CALLBACK`` (table index): ``new P(k)``; ``LOAD`` (descriptor, slot);
S15e.5g: ``FIELDM`` the ``M`` field; ``OWN`` (index) a generated memory member; ``BYTEM`` (load, maximum) a checked byte
member; ``STRING`` (text, length) ``ldc`` of a String.
"""

from __future__ import annotations

from xax_selfhost_facts import E
from xax_selfhost_jvm_code import _m
from xax_selfhost_jvm_method import M_ONE, OP
from xax_selfhost_views_backend import _call

# The fixed methods a lowering calls (``K_JAVA``): owner, name, descriptor.
JAVA = (
    ("java/lang/Integer", "toUnsignedLong", "(I)J"),
    ("java/lang/Long", "divideUnsigned", "(JJ)J"),
    ("java/lang/Long", "remainderUnsigned", "(JJ)J"),
    ("java/lang/Long", "rotateRight", "(JI)J"),
    ("java/lang/Integer", "rotateRight", "(II)I"),
    (None, "xax$pk", "(II)J"),  # the class's own shared member
    ("java/lang/Float", "floatToRawIntBits", "(F)I"),
    ("java/lang/Double", "doubleToRawLongBits", "(D)J"),
    ("java/lang/Float", "intBitsToFloat", "(I)F"),
    ("java/lang/Double", "longBitsToDouble", "(J)D"),
    ("java/lang/System", "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V"),
    ("java/util/Arrays", "copyOfRange", "([JII)[J"),
    ("java/lang/Long", "compareUnsigned", "(JJ)I"),
    ("java/lang/String", "getBytes", "(II[BI)V"),  # invokevirtual (S15e.5g)
    ("java/util/Arrays", "fill", "([BIIB)V"),  # stack storage (S15e.5h)
)
TRAP_LABEL = 0  # labels: block b is b, false stub NB + b, the trap 2 NB, a fresh one 2 NB + 1 + k


# -- the task stack -------------------------------------------------------------------------------------------------------


# -- get, put, constants, masks -------------------------------------------------------------------------------------------


# -- compares ---------------------------------------------------------------------------------------------------------


# -- lower_node ---------------------------------------------------------------------------------------------------------------


FLOAT_ARITHMETIC = {OP["FLOAT_ADD"]: (0x62, 0x63), OP["FLOAT_SUB"]: (0x66, 0x67), OP["FLOAT_MUL"]: (0x6A, 0x6B), OP["FLOAT_DIV"]: (0x6E, 0x6F)}


def run(e: E, kind: int, a=0, b=0, c=0):
    """Push one task and run the stack down to where it was."""
    p = e.p
    e.var("ru_base", _m(e, M_ONE))
    _call(e, "jl_push", kind, a, b, c, 0)
    _call(e, "jl_run", p["ru_base"])


