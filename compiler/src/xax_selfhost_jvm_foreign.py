"""S15e.5c (ADR-329): JVM reference types and platform calls in the XAX JVM program.

``xax_jvm._jvm_type`` gives a pointer to an identity-qualified opaque type ``jvm-ref:<descriptor>`` the reference
descriptor itself, and a pointer to a ``jvm-interface`` code entry the interface's class (a callback, ADR-161).  Here a
reference descriptor is a code ``D_REF + k``: the class's ``k``-th distinct descriptor text
(``jk_intern``), so equal descriptors are equal codes and slot typing stays integer comparison.

``jk_member`` is ``_foreign_member`` for the call kinds (``jvm-invokestatic``, ``-invokevirtual``, ``-getstatic``,
``-invokeinterface``, ``-invokestatic-interface``): the carrier's ABI (``JVM-FOREIGN-ABI``), the member text
(``JVM-FIELD-MEMBER``, ``JVM-METHOD-MEMBER``), the method descriptor (``JVM-METHOD-DESCRIPTOR``), the receiver of a
virtual or interface call, the arity (``JVM-FOREIGN-ARITY``) and each machine type against its descriptor
(``JVM-FOREIGN-DESCRIPTOR-TYPE``), each rejection written as the bootstrap's.  The object kinds (``jvm-new`` ...), the
memory class and a type the bootstrap cannot represent decline.

A member record (``MB_*``) holds its texts as words, one byte each: the class, the name, the descriptor, and per
parameter its text (the receiver ``L<class>;`` included) for the narrowing conversions and the arity diagnostic.
"""

from __future__ import annotations


REFERENCE_PREFIX = b"jvm-ref:"
MEMORY_CLASS = b"xax/jvm/Memory"


# -- interned reference descriptors -------------------------------------------------------------------------------------


# -- value types ----------------------------------------------------------------------------------------------------------


# -- the foreign member ---------------------------------------------------------------------------------------------------


