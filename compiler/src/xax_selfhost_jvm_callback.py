"""S15e.5e (ADR-331): JVM callbacks in the XAX JVM program (``xax_jvm._callbacks``, ADR-161).

``jk_table`` walks the closure's graphs before the methods: the function table (``_indirect_calls``: every
``FUNCTION_ADDRESS`` target, numbered from 1 in CID order) and the callback groups (a ``FUNCTION_ADDRESS`` whose result
points to a ``code-entry:jvm-interface:<interface>.<name>(<descriptor>)`` type): per (name, descriptor) the target
functions in first-seen order, and the interfaces in first-seen order.  A callback value is ``new P(k)``; the class
implements each interface method used, and that method calls the function whose table index ``k`` holds.

``jk_callbacks`` runs after the methods, as ``_callbacks`` does: the groups in (name, descriptor) order, each target's
signature (``JVM-ENTRY-SIGNATURE``), the interface method (``aload_0; getfield k``, a compare per target in table order,
the arguments, ``invokestatic``, the return; the trap) and ``<init>(I)V``.  An indirect call (``CALL_INDIRECT``) and
the shadow stack's rule belong to the general profile (declined).
"""

from __future__ import annotations

from xax_selfhost_facts import E


def _store(e: E, words, name: str):
    from xax_selfhost_jvm import _store_alloc

    return _store_alloc(e, words, name)


def _same_text(e: E, a, an, b, bn, name: str):
    p = e.p
    e.var(name, e.flag(e.eq(an, bn)))
    e.var(f"{name}_a", a)
    e.var(f"{name}_b", b)
    e.if_(e.ne(p[name], 0), lambda: e.for_(f"{name}_k", 0, an, lambda: e.if_(
        e.ne(e.ld(e.add(p[f"{name}_a"], p[f"{name}_k"])), e.ld(e.add(p[f"{name}_b"], p[f"{name}_k"]))), lambda: e.set(name, 0))))
    return p[name]


# -- the table and the groups ---------------------------------------------------------------------------------------------


# -- the members ------------------------------------------------------------------------------------------------------------


