"""Emitter for ``xax-construct-v1`` carriers (carrier authoring tooling in the XAX repository).

The native server's semantic graph is constructed from one carrier request; this module only helps write that
request.  Every block of a function takes the same parameter list (the function's variables), so mutable variables,
linear view tokens and the memory effect flow through every edge without hand-written phi bookkeeping.
"""

from __future__ import annotations

TYPES = {
    "mem": "win32.memory_effect", "fs": "win32.filesystem_effect", "proc": "win32.process_effect",
    "ptr": "win32.bytes_rw", "rptr": "win32.bytes_read", "u32p": "win32.u32_rw",
}


class Fn:
    """One carrier function.  ``views`` are byte views passed as (pointer, view token, memory effect) triples: the
    verifier tracks one memory-effect chain per storage, so each view ``V`` owns the variables ``Vp``, ``Vv``, ``Vm``."""

    def __init__(self, program: "Program", name: str, views: tuple[str, ...], params: list[tuple[str, str]],
                 returns: list[str], locals_: list[tuple[str, str]] = (), entry: bool = False):
        self.program, self.name, self.views, self.returns, self.is_entry = program, name, views, returns, entry
        if entry:  # the process entry receives one memory effect per view it will allocate
            self.params = [("proc", "proc"), ("fs", "fs"), *((f"{v}m", "mem") for v in views)]
        else:
            self.params = [p for v in views for p in self._triple(v)] + list(params)
        self.vars = [*self.params, *locals_]
        self.types = dict(self.vars)
        self.blocks: list[Block] = []
        self.entry = Block(self, entry=True)

    def _triple(self, v):
        return ((f"{v}p", self.program.ptr_type(v)), (f"{v}v", self.program.view_type(v)), (f"{v}m", "mem"))

    def block(self) -> "Block":
        return Block(self)

    def signature(self):
        """(param types, return types) as the carrier spells them."""
        if self.is_entry:
            return [t for _, t in self.params], ["b32", *(t for _, t in self.params)]
        scalar_returns = [self.types[r] if r in self.types else r for r in self.returns]
        view_returns = [t for v in self.views for _, t in self._triple(v)]
        return [t for _, t in self.params], [*scalar_returns, *view_returns]

    def carrier(self) -> dict:
        params, returns = self.signature()
        return {"name": self.name, "params": params, "returns": returns, "blocks": [b.carrier() for b in self.blocks]}


class Block:
    def __init__(self, fn: Fn, entry: bool = False):
        self.fn, self.index, self.nodes, self.end = fn, len(fn.blocks), [], None
        fn.blocks.append(self)
        names = fn.params if entry else fn.vars
        self.param_types = [t for _, t in names]
        self.env: dict[str, object] = {name: f"p{i}" for i, (name, _t) in enumerate(names)}
        self.produced = set(self.env.values())

    # -- values ---------------------------------------------------------------------------------------------------
    def _ref(self, value):
        if isinstance(value, str) and value in self.env:
            return self.env[value]
        if isinstance(value, int):
            raise TypeError("bare integer operand; use (type, value)")
        if isinstance(value, tuple):
            return [value[0], value[1]]
        if value not in self.produced:
            raise ValueError(f"{self.fn.name}: block {self.index} uses {value!r} from another block")
        return value

    def op(self, operation: str, operands, results, entity=None, attrs=None):
        node = [operation, [self._ref(v) for v in operands], list(results)]
        extra = {}
        if attrs is not None:
            extra["attrs"] = list(attrs)
        if entity is not None:
            extra["entity"] = entity
        if extra:
            node.append(extra)
        index = len(self.nodes)
        self.nodes.append(node)
        refs = [f"n{index}" if k == 0 else f"n{index}.r{k}" for k in range(len(results))]
        self.produced.update(refs)
        return refs

    def op1(self, operation, operands, result, **kw):
        return self.op(operation, operands, [result], **kw)[0]

    def set(self, name: str, value) -> None:
        assert name in self.fn.types, name
        self.env[name] = self._ref(value)

    def get(self, name: str):
        return self.env[name]

    # arithmetic over b32 unless stated
    def add(self, a, b, t="b32"): return self.op1("add.wrap", [a, b], t)
    def sub(self, a, b, t="b32"): return self.op1("sub.wrap", [a, b], t)
    def mul(self, a, b, t="b32"): return self.op1("mul.wrap", [a, b], t)
    def band(self, a, b, t="b32"): return self.op1("bit.and", [a, b], t)
    def bor(self, a, b, t="b32"): return self.op1("bit.or", [a, b], t)
    def bxor(self, a, b, t="b32"): return self.op1("bit.xor", [a, b], t)
    def udiv(self, a, b, t="b32"): return self.op1("udiv", [a, b], t)
    def cmp(self, kind, a, b): return self.op1("int.compare", [a, b], "b1", attrs=[kind])
    def zext(self, a, t="b32"): return self.op1("int.zero.extend", [a], t)
    def trunc(self, a, t="b32"): return self.op1("int.truncate", [a], t)
    def flag(self, kind, a, b): return self.zext(self.cmp(kind, a, b))

    # memory over byte views (dynamic b32 byte offsets, ADR-231 widths)
    def load(self, view: str, offset, width: int = 1) -> str:
        value, mem = self.op("checked.load.bits.le", [f"{view}p", offset, f"{view}m"], [f"b{8 * width}", "mem"],
                             attrs=[width, 1])
        self.set(f"{view}m", mem)
        return value if width == 4 else self.zext(value) if width < 4 else value

    def store(self, view: str, offset, value, width: int = 1) -> None:
        if isinstance(value, str) and width < 4 and not isinstance(self._ref(value), list):
            value = self.trunc(value, f"b{8 * width}")
        elif isinstance(value, tuple):
            value = (f"b{8 * width}", value[1])
        (mem,) = self.op("checked.store.bits.le", [f"{view}p", offset, value, f"{view}m"], ["mem"], attrs=[width, 1])
        self.set(f"{view}m", mem)

    def call(self, callee: Fn, *args, into: tuple[str, ...] = ()):
        """Direct call; threads the callee's views (same names in the caller); binds scalar results."""
        operands = [name for v in callee.views for name in (f"{v}p", f"{v}v", f"{v}m")] + list(args)
        _params, returns = callee.signature()
        refs = self.op("call.direct", operands, returns, entity={"fn": callee.name})
        scalars = len(callee.returns)
        for k, v in enumerate(callee.views):
            for j, suffix in enumerate("pvm"):
                self.set(f"{v}{suffix}", refs[scalars + 3 * k + j])
        for name, ref in zip(into, refs[:scalars]):
            self.set(name, ref)
        return refs[:scalars]

    # -- terminators ----------------------------------------------------------------------------------------------
    def _args(self, target: "Block"):
        return [self.env[name] for name, _t in self.fn.vars]

    def jump(self, target: "Block") -> None:
        assert self.end is None
        self.end = ["br", target.index, self._args(target)]

    def branch(self, cond, if_true: "Block", if_false: "Block") -> None:
        assert self.end is None
        self.end = ["cbr", self._ref(cond), if_true.index, self._args(if_true), if_false.index, self._args(if_false)]

    def if_(self, cond) -> tuple["Block", "Block"]:
        """End this block with a branch on ``cond`` (b1); returns (then, join)."""
        then, join = self.fn.block(), self.fn.block()
        self.branch(cond, then, join)
        return then, join

    def ret(self, *values) -> None:
        assert self.end is None
        views = [name for v in self.fn.views for name in (f"{v}p", f"{v}v", f"{v}m")]
        self.end = ["ret", [self._ref(v) for v in (*values, *views)]]

    def ret_raw(self, *values) -> None:
        self.end = ["ret", [self._ref(v) for v in values]]

    def carrier(self) -> dict:
        assert self.end is not None, f"{self.fn.name}: block {self.index} has no end"
        return {"params": self.param_types, "nodes": self.nodes, "end": self.end}


class Program:
    def __init__(self, name: str, views: dict[str, int], pointers: dict[str, str] = None):
        self.name, self.views, self.fns, self.pointers = name, views, [], pointers or {}

    def ptr_type(self, view: str) -> str:
        return self.pointers.get(view, "ptr")

    def view_type(self, view: str) -> str:
        return f"v{view}"

    def fn(self, *args, **kw) -> Fn:
        f = Fn(self, *args, **kw)
        self.fns.append(f)
        return f

    def _callees_first(self) -> list[Fn]:
        """The carrier lists callees before callers."""
        by_name, order, seen = {f.name: f for f in self.fns}, [], set()

        def visit(f: Fn) -> None:
            if f.name in seen:
                return
            seen.add(f.name)
            for block in f.blocks:
                for node in block.nodes:
                    entity = node[3].get("entity") if len(node) == 4 else None
                    if isinstance(entity, dict) and "fn" in entity:
                        visit(by_name[entity["fn"]])
            order.append(f)

        for f in self.fns:
            visit(f)
        return order

    def carrier(self, entries: dict[str, str], release: str) -> dict:
        types = dict(TYPES)
        types.update({f"v{v}": {"view": extent} for v, extent in self.views.items()})
        return {"format": "xax-construct-v1", "platform": "windows-x86_64", "types": types,
                "functions": [f.carrier() for f in self._callees_first()],
                "package": {"name": self.name, "entries": entries, "release": release}}
