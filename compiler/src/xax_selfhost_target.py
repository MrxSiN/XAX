"""Self-hosting step S4d.2d (ADR-139): ``target.op`` verification as XAX semantics.

``_verify_target_node`` decodes the node's target package with
``decode_native_target`` (every field, list, enum, and machine-profile rule)
and checks the node against the declared operation contract: attributes,
scope, memory spaces, arity, operand and result constraints, resource
transitions, and effect continuation.  The helper built here does the same
over the target body in the typing input stream, one word per body byte, and
declines (``NONE``) wherever the bootstrap would raise or where a value does
not fit the canonical five-byte ULEBs the typing decoder reads; on decline the
bootstrap raises the exact diagnostic.
"""

from __future__ import annotations

import xax_compiler as _X
import xax_selfhost_typing as _T
from xax_compiler import Kind, Operation, TerminatorKind
from xax_selfhost_facts import E, M, NONE, H_COUNT, _Node, _function, _reject, _require, _uleb

SCOPES = (1, 3)  # AtomicScope values
FAMILIES = (1, 5)  # AtomicFamily values
DOMAINS = (1, 11)  # EffectDomain values
CONSTRAINTS = (1, 5)  # TargetValueConstraintKind values
BITS, RESOURCE, EFFECT, FUNCTION_POINTER, POINTER = range(1, 6)
OPAQUE_FUNCTION = int(_X.OpaqueKind.FUNCTION)


def _ranges(values):
    """Sorted inclusive ranges covering exactly ``values``."""
    ranges = []
    for value in sorted(set(int(item) for item in values)):
        if ranges and ranges[-1][1] + 1 == value:
            ranges[-1][1] = value
        else:
            ranges.append([value, value])
    return ranges


def _member(e: E, value, values):
    return e.either(*(e.both(e.le(low, value), e.le(value, high)) for low, high in _ranges(values)))


class _Reader:
    """A cursor over input words ``[at, end)``; every read past ``end`` declines."""

    def __init__(self, e: E, at: str, end: str):
        self.e, self.at, self.end = e, at, end

    def uleb(self, name: str):
        e, p = self.e, self.e.p
        value, size, ok = _uleb(e, p[self.at])
        _require(e, ok)
        e.set(self.at, e.add(p[self.at], size))
        _require(e, e.le(p[self.at], p[self.end]))
        e.var(name, value)
        return p[name]

    def flag_byte(self, name: str):
        """One raw byte that must be 0 or 1 (``TARGET-*-BOOL``)."""
        e, p = self.e, self.e.p
        _require(e, e.lt(p[self.at], p[self.end]))
        e.var(name, e.rd(p[self.at]))
        _require(e, e.le(p[name], 1))
        e.set(self.at, e.add(p[self.at], 1))
        return p[name]

    def blob(self, name: str):
        """A byte string; ``name`` holds its length."""
        e, p = self.e, self.e.p
        self.uleb(name)
        e.set(self.at, e.add(p[self.at], p[name]))
        _require(e, e.le(p[self.at], p[self.end]))
        return p[name]

    def listing(self, loop: str, strict=None, check=None, each=None):
        """A ULEB list ``[count, values]``; returns the count variable's value.

        ``strict`` (a condition, or True): each value exceeds the previous.  ``check(value)``
        must hold for each value; ``each(value, k)`` runs after the checks."""
        e, p = self.e, self.e.p
        self.uleb(f"{loop}_count")
        e.var(f"{loop}_previous", 0)

        def body():
            value = self.uleb(f"{loop}_value")
            if strict is not None:
                increasing = e.either(e.eq(p[loop], 0), e.lt(p[f"{loop}_previous"], value))
                _require(e, increasing if strict is True else e.either(e.not_(strict), increasing))
            if check is not None:
                _require(e, check(p[f"{loop}_value"]))
            if each is not None:
                each(p[f"{loop}_value"], p[loop])
            e.set(f"{loop}_previous", p[f"{loop}_value"])

        e.for_(loop, 0, p[f"{loop}_count"], body)
        return p[f"{loop}_count"]


def _scope_bit(e: E, scope):
    return e.sel(e.eq(scope, 1), 2, e.sel(e.eq(scope, 2), 4, e.sel(e.eq(scope, 3), 8, 0)))


NO_CONTRACT = NONE - 1  # ``_target_contract``: a valid target that declares no contract for the operation


def _target_contract(tables):
    """``decode_native_target`` over a target object: the input position of the contract for operation ``wanted``,
    ``NO_CONTRACT``, or NONE (a target the bootstrap rejects, or one with no contracts).  S8 (ADR-251): a helper
    of its own, so ``target.op`` stays within the backend's per-function limits."""

    def build(e: E):
        p = e.p
        member = lambda value, bounds: e.both(e.le(bounds[0], value), e.le(value, bounds[1]))  # noqa: E731
        entity = p["entity"]
        _require(e, e.lt(entity, e.hd(H_COUNT)))
        position = e.table(_T.POSITION, entity)
        _require(e, e.both(e.eq(e.rd(position), int(Kind.TARGET)), e.eq(e.rd(e.add(position, 1)), 0)))
        e.var("t_at", e.add(position, 3))
        e.var("t_end", e.add(e.add(position, 3), e.rd(e.add(position, 2))))
        r = _Reader(e, "t_at", "t_end")
        _require(e, e.ne(r.blob("identity"), 0))
        _require(e, e.lt(p["t_at"], p["t_end"]))  # a native profile, not an identity-only carrier
        profile, arch, abi, image, word_bits, pointer_bits = (r.uleb(name) for name in ("profile", "arch", "abi", "image", "word_bits", "pointer_bits"))
        e.var("stack_alignment", 1)
        e.var("shadow", 0)
        x86 = lambda: e.eq(p["arch"], 1)  # noqa: E731

        def registers():
            r.uleb("stack_alignment")
            r.uleb("shadow")
            # Windows x64: arguments (1, 2, 8, 9), result 0, scratch (10, 11); AAPCS64: 0..7, 0, (9, 10).
            r.listing("argument", each=lambda value, k: _require(e, e.eq(value, e.sel(x86(), e.sel(e.eq(k, 0), 1, e.sel(e.eq(k, 1), 2, e.add(k, 6))), k))))
            _require(e, e.eq(p["argument_count"], e.sel(x86(), 4, 8)))
            _require(e, e.eq(r.uleb("result_register"), 0))
            r.listing("scratch", each=lambda value, k: _require(e, e.eq(value, e.add(e.sel(x86(), 10, 9), k))))
            _require(e, e.eq(p["scratch_count"], 2))

        e.if_(e.either(e.eq(arch, 1), e.eq(arch, 3)), registers,
              lambda: _require(e, _member(e, p["arch"], (2, 4, _X.JVM_ARCHITECTURE, _X.RISCV64_ARCHITECTURE, _X.SPIRV_ARCHITECTURE))))
        r.listing("operation", strict=True, check=lambda value: _member(e, value, [item.value for item in Operation]))
        r.listing("terminator", strict=True, check=lambda value: _member(e, value, [item.value for item in TerminatorKind]))
        board = _X.BOARD_PROFILE

        def concurrency():
            r.listing("atomic_width", strict=True, check=lambda value: e.ne(value, 0))
            r.listing("atomic_scope", strict=True, check=lambda value: member(value, SCOPES))
            r.listing("atomic_family", strict=True, check=lambda value: member(value, FAMILIES))
            e.var("event_previous", 0)

            def handler():
                event = r.uleb("event")
                _require(e, e.either(e.eq(p["h"], 0), e.lt(p["event_previous"], event)))
                e.set("event_previous", p["event"])
                for k in range(6):
                    r.uleb(f"handler_field{k}")
                r.listing("domain", strict=True, check=lambda value: member(value, DOMAINS))
                _require(e, e.ne(r.uleb("stack_bound"), 0))
                r.uleb("return_contract")

            e.for_("h", 0, r.uleb("handlers"), handler)

        e.if_(e.either(e.eq(p["profile"], 2), e.eq(p["profile"], board)), concurrency)
        e.var("accelerator_scopes", 0)
        e.var("spaces", 0)
        e.var("space_count", 0)

        def accelerator():
            # Stage S4d.2d models accelerator packages only for the accelerator architecture.
            _require(e, e.eq(p["arch"], 4))
            _require(e, e.ne(r.uleb("lanes"), 0))
            _require(e, e.ne(r.uleb("groups"), 0))
            r.listing("accelerator_scope", strict=True, check=lambda value: member(value, SCOPES),
                      each=lambda value, k: e.set("accelerator_scopes", e.or_(p["accelerator_scopes"], _scope_bit(e, value))))
            _require(e, e.ne(p["accelerator_scopes"], 0))
            r.uleb("space_count")
            _require(e, e.ne(p["space_count"], 0))
            e.set("spaces", e.alloc(p["space_count"]))
            _require(e, e.ne(p["spaces"], NONE))

            def space():
                identity = r.uleb("space_id")
                _require(e, e.either(e.eq(p["s"], 0), e.lt(e.ld(e.add(p["spaces"], e.sub(p["s"], 1))), identity)))
                e.st(e.add(p["spaces"], p["s"]), p["space_id"])
                _require(e, e.ne(r.uleb("address_bits"), 0))
                _require(e, e.ne(r.uleb("unit_bits"), 0))
                _require(e, e.power_of_two(r.uleb("space_alignment")))
                r.listing("width", strict=True, check=lambda value: e.ne(value, 0))
                r.listing("visibility", strict=True, check=lambda value: member(value, SCOPES))
                r.flag_byte("host")
                r.flag_byte("device")

            e.for_("s", 0, p["space_count"], space)

        e.if_(e.eq(p["profile"], 3), accelerator)
        e.var("contracts", 0)
        e.var("match", NONE)
        checked = lambda: e.either(e.eq(p["profile"], 3), e.eq(p["profile"], 4))  # noqa: E731

        def contracts():
            e.var("id_previous", 0)

            def contract():
                start = p["t_at"]
                e.var("contract_start", start)
                identity = r.uleb("operation_id")
                _require(e, e.either(e.not_(checked()), e.eq(p["c"], 0), e.lt(p["id_previous"], identity)))
                e.set("id_previous", p["operation_id"])
                e.if_(e.both(e.eq(p["match"], NONE), e.eq(p["operation_id"], p["wanted"])), lambda: e.set("match", p["contract_start"]))
                _require(e, e.either(e.not_(checked()), e.ne(r.uleb("semantic"), 0)))
                _require(e, e.either(e.ne(p["profile"], 3), e.le(r.uleb("opcode"), 255)))
                for signature in ("operand", "result"):
                    def constraint(signature=signature):
                        kind, primary, secondary = (r.uleb(f"{signature}_{field}") for field in ("kind", "primary", "secondary"))
                        _require(e, member(kind, CONSTRAINTS))
                        valid = e.either(
                            e.both(e.eq(kind, BITS), e.ne(primary, 0), e.eq(secondary, 0)),
                            e.both(e.eq(kind, RESOURCE), e.ne(primary, 0), e.ne(secondary, 0)),
                            e.both(e.eq(kind, EFFECT), member(primary, DOMAINS)),
                            e.both(e.le(FUNCTION_POINTER, kind), e.eq(primary, 0), e.eq(secondary, 0)),
                        )
                        _require(e, e.either(e.not_(checked()), valid))

                    e.for_(f"{signature}_k", 0, r.uleb(f"{signature}_constraints"), constraint)
                e.var("contract_scopes", 0)
                r.listing("contract_scope", strict=checked(), check=lambda value: member(value, SCOPES),
                          each=lambda value, k: e.set("contract_scopes", e.or_(p["contract_scopes"], _scope_bit(e, value))))
                _require(e, e.either(e.not_(checked()), e.ne(p["contract_scopes"], 0)))
                _require(e, e.either(e.ne(p["profile"], 3), e.eq(e.and_(p["contract_scopes"], p["accelerator_scopes"]), p["contract_scopes"])))
                for name in ("source_space", "destination_space"):
                    r.uleb(name)

                    def known(name=name):
                        e.var("known_space", 0)
                        e.for_("q", 0, p["space_count"], lambda: e.if_(e.eq(e.ld(e.add(p["spaces"], p["q"])), p[name]), lambda: e.set("known_space", 1)))
                        _require(e, e.ne(p["known_space"], 0))

                    e.if_(e.eq(p["profile"], 3), known)
                r.flag_byte("synchronizes")
                r.flag_byte("may_block")
                dependency = r.blob("dependency")
                _require(e, e.either(e.not_(checked()), e.eq(dependency, 0), e.eq(dependency, 32)))

            e.for_("c", 0, r.uleb("contracts"), contract)
            _require(e, e.either(e.not_(checked()), e.ne(p["contracts"], 0)))

        e.if_(e.either(e.eq(p["profile"], 3), e.eq(p["profile"], 4), e.eq(p["profile"], board)), contracts)
        _require(e, e.eq(p["t_at"], p["t_end"]))
        _require(e, e.both(e.le(1, p["profile"]), e.le(p["profile"], board)))
        machine = (p["abi"], p["image"], p["word_bits"], p["pointer_bits"], p["stack_alignment"], p["shadow"])

        def one_of(values, allowed):
            return e.either(*(e.both(*(e.eq(value, item) for value, item in zip(values, row))) for row in allowed))

        arch, profile = p["arch"], p["profile"]
        five = (profile, p["abi"], p["image"], p["word_bits"], p["pointer_bits"])
        rules = [
            e.both(e.eq(arch, 1), one_of(machine, ((1, 1, 64, 64, 16, 32), (_X.X86_64_LINUX_ABI, _X.X86_64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 32),
                                                  (_X.X86_64_LINUX_ABI, _X.X86_64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 32)))),
            e.both(e.eq(arch, _X.RISCV64_ARCHITECTURE), one_of(five, ((1, _X.RISCV64_LP64_ABI, _X.RISCV64_RAW_FORMAT, 64, 64),))),
            e.both(e.eq(arch, _X.SPIRV_ARCHITECTURE), one_of(five, ((1, _X.SPIRV_VULKAN_ABI, _X.SPIRV_MODULE_FORMAT, 32, 32),))),
            e.both(e.eq(arch, _X.JVM_ARCHITECTURE), one_of(five, ((1, _X.JVM_ABI, _X.JVM_JAR_FORMAT, 64, 64),))),
            e.both(e.eq(arch, 2), one_of(five[1:], ((2, 2, 64, 32),))),
            e.both(
                e.eq(arch, 3),
                one_of(machine, ((3, 1, 64, 64, 16, 0), (4, _X.ANDROID_ELF_FORMAT, 64, 64, 16, 0), (4, _X.ANDROID_ELF_PACKED_FORMAT, 64, 64, 16, 0),
                                 (_X.AARCH64_LINUX_ABI, _X.AARCH64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 0),
                                 (_X.AARCH64_LINUX_ABI, _X.AARCH64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 0), (3, _X.AARCH64_BOARD_ELF_FORMAT, 64, 64, 16, 0))),
                e.either(e.ne(p["abi"], 4), e.eq(profile, 4)),
                e.either(e.ne(p["abi"], _X.AARCH64_LINUX_ABI), e.eq(profile, 1)),
                e.either(e.ne(p["abi"], 3), e.eq(profile, 1), e.eq(profile, 2), e.eq(profile, board)),
                e.eq(e.flag(e.eq(p["image"], _X.AARCH64_BOARD_ELF_FORMAT)), e.flag(e.eq(profile, board))),
            ),
            e.both(e.eq(arch, 4), one_of(five, ((3, 4, 3, 32, 64),))),
        ]
        _require(e, e.either(*rules))
        _require(e, e.ne(p["contracts"], 0))
        e.give(e.sel(e.eq(p["match"], NONE), NO_CONTRACT, p["match"]))

    return _function(("entity", "wanted"), build, tables)


def _target_op(tables, contract):
    """``_verify_target_node`` for one ``target.op`` node; the next node cursor, or NONE."""

    def build(e: E):
        p = e.p
        n = _Node(e)
        member = lambda value, bounds: e.both(e.le(bounds[0], value), e.le(value, bounds[1]))  # noqa: E731
        entity = n.entity
        e.var("match", e.call(contract, entity, n.attr(0)))
        _require(e, e.ne(p["match"], NONE))
        position = e.table(_T.POSITION, entity)
        e.var("t_at", p["match"])
        e.var("t_end", e.add(e.add(position, 3), e.rd(e.add(position, 2))))
        r = _Reader(e, "t_at", "t_end")
        # S8 (ADR-251): each check below is ``_verify_target_node``'s, in its order, with its exact rejection.
        _reject(e, e.eq(n.na, 4), M["TARGET_ATTRIBUTES"], n.na)
        _reject(e, e.ne(p["match"], NO_CONTRACT), M["TARGET_DEFINED"], entity, n.attr(0))
        scope = n.attr(1)
        e.set("t_at", p["match"])
        for name in ("operation_id", "semantic", "opcode"):
            r.uleb(name)
        for signature in ("operand", "result"):  # skipped here: scope and spaces come first
            r.uleb(f"{signature}_constraints")
            e.var(f"{signature}_at", p["t_at"])
            e.for_(f"{signature}_skip", 0, p[f"{signature}_constraints"], lambda: [r.uleb(f"skip{k}") for k in range(3)])
        e.var("scope_supported", 0)
        r.listing("contract_scope", each=lambda value, k: e.if_(e.eq(value, scope), lambda: e.set("scope_supported", 1)))
        _reject(e, member(scope, SCOPES), M["TARGET_SCOPE_ENUM"], scope)
        _reject(e, e.ne(p["scope_supported"], 0), M["TARGET_SCOPE_SUPPORTED"], entity, n.attr(0), scope)
        _reject(e, e.both(e.eq(r.uleb("source_space"), n.attr(2)), e.eq(r.uleb("destination_space"), n.attr(3))), M["TARGET_SPACES"],
                entity, n.attr(0), n.attr(2), n.attr(3))
        _reject(e, e.both(e.eq(p["operand_constraints"], n.no), e.eq(p["result_constraints"], n.nr)), M["TARGET_ARITY"],
                p["operand_constraints"], p["result_constraints"], n.no, n.nr)
        kinds = {}
        for label, (signature, count, type_of) in enumerate((("operand", n.no, n.tid), ("result", n.nr, n.rtid))):
            e.set("t_at", p[f"{signature}_at"])
            kinds[signature] = e.alloc(e.add(count, 1))
            e.var(f"{signature}_kinds", kinds[signature])
            _require(e, e.ne(p[f"{signature}_kinds"], NONE))

            def matches(signature=signature, type_of=type_of, label=label):
                k = p[f"{signature}_k"]
                kind, primary, secondary = (r.uleb(f"{signature}_{field}") for field in ("kind", "primary", "secondary"))
                e.st(e.add(p[f"{signature}_kinds"], k), kind)
                type_index = e.rd(e.add(n.tids_at if signature == "operand" else n.rt_at, k))
                element = e.table(_T.PELEM, type_index)
                pointer = e.ne(e.table(_T.PTR, type_index), 0)
                width = e.table(_T.WIDTH, type_index)
                _reject(e, e.either(
                    e.both(e.eq(kind, BITS), e.ne(width, 0), e.eq(width, primary), e.eq(secondary, 0)),
                    e.both(e.eq(kind, RESOURCE), e.ne(e.table(_T.RESOURCE, type_index), 0), e.eq(e.table(_T.RKIND, type_index), primary), e.eq(e.table(_T.RSTATE, type_index), secondary)),
                    e.both(e.eq(kind, EFFECT), e.ne(e.table(_T.EFFECT, type_index), 0), e.eq(e.table(_T.EDOMAIN, type_index), primary), e.eq(e.table(_T.EINST, type_index), secondary)),
                    e.both(e.eq(kind, FUNCTION_POINTER), e.eq(primary, 0), e.eq(secondary, 0), pointer, e.eq(e.table(_T.OPAQUE, element), OPAQUE_FUNCTION)),
                    e.both(e.eq(kind, POINTER), e.eq(primary, 0), e.eq(secondary, 0), pointer),
                ), M["TARGET_TYPE"], label, k, kind, primary, secondary, type_index)

            e.for_(f"{signature}_k", 0, count, matches)

        # Resource transitions between same-kind, same-instance operand and result resources.
        def transitions():
            def pair():
                source, target = n.tid(p["i"]), n.rtid(p["o"])
                same = e.both(
                    e.eq(e.ld(e.add(p["operand_kinds"], p["i"])), RESOURCE), e.eq(e.ld(e.add(p["result_kinds"], p["o"])), RESOURCE),
                    e.eq(e.table(_T.RKIND, source), e.table(_T.RKIND, target)), e.eq(e.table(_T.RINSTANCE, source), e.table(_T.RINSTANCE, target)),
                )

                def check():
                    state = e.table(_T.RSTATE, target)
                    e.var("reachable", e.flag(e.eq(e.table(_T.RSTATE, source), state)))
                    e.for_("t", 0, e.table(_T.TCOUNT, source), lambda: e.if_(
                        e.eq(e.ld(e.add(e.table(_T.TSTART, source), p["t"])), state), lambda: e.set("reachable", 1)))
                    _require(e, e.ne(p["reachable"], 0))

                e.if_(same, check)

            e.for_("o", 0, n.nr, pair)

        e.for_("i", 0, n.no, transitions)
        # Effect continuation: the effect-constrained operand types equal the effect-constrained result types, in order.
        e.var("o", 0)

        def effect_operand():
            def advance():
                e.while_(lambda: e.both(e.lt(p["o"], n.nr), e.ne(e.ld(e.add(p["result_kinds"], p["o"])), EFFECT)), lambda: e.set("o", e.add(p["o"], 1)))
                _require(e, e.lt(p["o"], n.nr))
                _require(e, e.eq(n.tid(p["i"]), n.rtid(p["o"])))
                e.set("o", e.add(p["o"], 1))

            e.if_(e.eq(e.ld(e.add(p["operand_kinds"], p["i"])), EFFECT), advance)

        e.for_("i", 0, n.no, effect_operand)
        e.for_("o", p["o"], n.nr, lambda: _require(e, e.ne(e.ld(e.add(p["result_kinds"], p["o"])), EFFECT)))
        e.give(n.next)

    return _function(("cursor", "block"), build, tables)
