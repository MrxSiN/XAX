"""S15f.4 (ADR-325): bare-metal AArch64 load images (``aarch64-baremetal-load-image-v1``, ``-atomic-v1``, ``-v2``) for
the differential tests of the XAX AArch64 program.

``aarch64_raw_case(rng, kind)`` gives ``(reader, entry, target, name)``:

* ``legacy``: functions for the legacy register path on the v1 and atomic profiles: 32/64-bit wrapping arithmetic
  over many simultaneously live values (register pressure, spills), constants of every width, direct calls with
  values live across them, stack storage, a conditional branch on a ``bits<1>`` value to two blocks that use the
  entry's values (homes) and join with up to twelve block parameters (edge spill slots), a back edge, and traps;
* ``eligible``: functions the v2 profile lowers on the legacy register path (``_register_path_eligible``): the same
  shapes with integer compares as conditions and loops;
* ``general``: ``x86_raw_corpus``'s random functions on the v2 profile (the frame path, one slot per value);
* ``random``: ``x86_raw_corpus``'s random functions on any of the three (narrow arithmetic the legacy path rejects).
"""

from __future__ import annotations

import random

from xax_compiler import (
    IntCompare, Operation, Permission, XaxError, aarch64_baremetal_atomic_target, aarch64_baremetal_general_target, aarch64_baremetal_target,
    bits_type, decode_native_target, memory_effect_type, pointer_type, stack_owner_type,
)
from xax_graph_builder import GraphBuilder, program_store

import x86_raw_corpus as X

B1, B8, B16, B32, B64 = (bits_type(w) for w in (1, 8, 16, 32, 64))
WIDE = (B32, B64)
WIDTH = {B1: 1, B8: 8, B16: 16, B32: 32, B64: 64}
LEGACY_TARGETS = (aarch64_baremetal_target, aarch64_baremetal_atomic_target)
TRAPS = (b"", b"\x05", b"\xc8\x01")


class _Values:
    def __init__(self, rng, block):
        self.rng, self.block, self.values = rng, block, {B32: [], B64: []}

    def add(self, t, value):
        self.values.setdefault(t, []).append(value)
        return value

    def pick(self, t):
        items = self.values.get(t)
        if items and self.rng.random() < 0.85:
            return self.rng.choice(items)
        return self.add(t, self.block.const(t, self.rng.randrange(1 << WIDTH[t])))

    def arithmetic(self, count):
        for _ in range(count):
            t = self.rng.choice(WIDE)
            op = self.rng.choice((Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP))
            self.add(t, self.block.op1(op, (self.pick(t), self.pick(t)), t))

    def fold(self, t):
        """Every value of type ``t`` added into one (so all stay live until the end)."""
        items = list(self.values.get(t) or [self.pick(t)])
        self.rng.shuffle(items)
        total = items[0]
        for item in items[1:]:
            total = self.block.op1(self.rng.choice((Operation.ADD_WRAP, Operation.SUB_WRAP)), (total, item), t)
        return self.add(t, total)


def _condition(rng, values: _Values, compare: bool, flags):
    block = values.block
    if compare:
        t = rng.choice(WIDE)
        return block.op1(Operation.INT_COMPARE, (values.pick(t), values.pick(t)), B1, attributes=(rng.choice(list(IntCompare)),))
    if flags and rng.random() < 0.6:
        return rng.choice(flags)
    return block.const(B1, rng.randrange(2))


def _legacy_function(rng, objects: list, compare: bool, stack: bool, depth: int = 0):
    """A function the legacy register path lowers (on v1/atomic: no compares; on v2: no stack storage)."""
    params = tuple(rng.choice(WIDE + (B1,) if not compare and rng.random() < 0.2 else WIDE) for _ in range(rng.randrange(0, 9)))
    result = rng.choice(WIDE)
    graph = GraphBuilder()
    entry = graph.block(*params)
    values = _Values(rng, entry)
    flags = []
    for t, value in zip(params, entry.params):
        (flags.append(value) if t == B1 else values.add(t, value))
    values.arithmetic(rng.randrange(2, 8))
    for _ in range(rng.randrange(0, 4)):
        values.block.const(rng.choice((B1, B8, B16, B32, B64)), rng.randrange(256))  # constants never used
    if stack and rng.random() < 0.5:
        element = rng.choice((B8, B16, B32, B64))
        size, count = WIDTH[element] // 8, rng.choice((1, 2, 4))
        owner_type, memory_type = stack_owner_type(), memory_effect_type()
        pointer = pointer_type(element, Permission.READ_WRITE, size)
        objects += [owner_type, memory_type, pointer]
        base, owner, memory = entry.op(Operation.STACK_ALLOC, (), (pointer, owner_type, memory_type), attributes=(size * count, size))
        for k in range(count):
            at = entry.op1(Operation.ADDRESS_OFFSET, (base,), pointer, attributes=(k * size,)) if k else base
            stored = values.pick(element) if element in WIDE else entry.const(element, rng.randrange(1 << WIDTH[element]))
            memory = entry.op1(Operation.STORE_BITS_LE, (at, stored, memory), memory_type, attributes=(size, 1))
        loaded, memory = entry.op(Operation.LOAD_BITS_LE, (base, memory), (element, memory_type), attributes=(size, 1))
        if element in WIDE:
            values.add(element, loaded)
        entry.op(Operation.STACK_END, (owner, memory), ())
    if rng.random() < 0.5:
        values.arithmetic(rng.randrange(8, 20))  # register pressure
    if depth < 2 and rng.random() < 0.5:
        for _ in range(rng.randrange(1, 3)):
            callee, callee_params, callee_result = _legacy_function(rng, objects, compare, stack, depth + 1)
            values.add(callee_result, entry.op1(Operation.CALL_DIRECT, tuple(values.pick(t) if t != B1 else entry.const(B1, 1) for t in callee_params),
                                                callee_result, entity=callee))
            values.arithmetic(rng.randrange(0, 3))
    shape = rng.randrange(4)
    if shape == 0:
        entry.ret(values.fold(result))
    else:
        # A diamond: the entry's values used in both arms (homes), joined by up to twelve parameters.
        join_types = tuple(rng.choice(WIDE) for _ in range(rng.randrange(1, 13)))
        left, right, join = graph.block(), graph.block(), graph.block(*join_types)
        condition = _condition(rng, values, compare, flags)
        if shape == 3:
            trap = graph.block()
            trap.trap(rng.choice(TRAPS))
            guard = graph.block()
            entry.cbr(condition, guard, (), trap, ())
            guard_values = _Values(rng, guard)
            guard_values.values = {t: list(items) for t, items in values.values.items()}
            guard.cbr(_condition(rng, guard_values, compare, flags), left, (), right, ())
        else:
            entry.cbr(condition, left, (), right, ())
        for arm in (left, right):
            arm_values = _Values(rng, arm)
            arm_values.values = {t: list(items) for t, items in values.values.items()}
            arm_values.arithmetic(rng.randrange(0, 6))
            arm.br(join, *(arm_values.pick(t) for t in join_types))
        join_values = _Values(rng, join)
        join_values.values = {t: list(items) for t, items in values.values.items()}
        for t, value in zip(join_types, join.params):
            join_values.add(t, value)
        join_values.arithmetic(rng.randrange(0, 4))
        if rng.random() < 0.4:
            # A back edge: a loop over (value, flag) that runs once more, or (with compares) a counted loop.
            loop, done = graph.block(result, B32 if compare else B1), graph.block(result)
            first = join_values.fold(result)
            join.br(loop, first, join.const(B32, rng.randrange(1, 4)) if compare else join.const(B1, 1))
            value, control = loop.params
            step = loop.op1(Operation.MUL_WRAP, (value, loop.const(result, 3)), result)
            if compare:
                more = loop.op1(Operation.INT_COMPARE, (control, loop.const(B32, 0)), B1, attributes=(IntCompare.NE,))
                loop.cbr(more, loop, (step, loop.op1(Operation.SUB_WRAP, (control, loop.const(B32, 1)), B32)), done, (value,))
            else:
                loop.cbr(control, loop, (step, loop.const(B1, 0)), done, (value,))
            done.ret(done.params[0])
        else:
            join.ret(join_values.fold(result))
    function = graph.function(params, (result,))
    objects += [*graph.objects.values(), B1, B8, B16, B32, B64]
    return function, params, result


def aarch64_raw_case(rng: random.Random, kind: str):
    """``(reader, entry, target, name)``; a program the verifier rejects is drawn again."""
    while True:
        if kind == "legacy":
            target = rng.choice(LEGACY_TARGETS)()
        elif kind in ("eligible", "general"):
            target = aarch64_baremetal_general_target()
        else:
            target = rng.choice(LEGACY_TARGETS + (aarch64_baremetal_general_target,))()
        identity = decode_native_target(target).identity.decode()
        objects: list = []
        try:
            if kind in ("legacy", "eligible"):
                entry, _params, _result = _legacy_function(rng, objects, kind == "eligible", kind == "legacy")
            else:
                entry, _params = X._function(rng, set(decode_native_target(target).supported_operations), objects, None)
            return program_store(entry, target, tuple(objects)), entry, target, f"{identity} {kind}"
        except (XaxError, ValueError, KeyError, AttributeError, TypeError):
            continue
