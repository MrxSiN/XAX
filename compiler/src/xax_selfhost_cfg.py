"""Self-hosting step S3d (ADR-121): graph control-flow analysis as XAX semantics.

After a graph body parses, the verifier checks every branch target, computes
each block's dominator set, and orders blocks in reverse postorder of a
depth-first walk from the entry (unreached blocks after, by index).  One XAX
function does all three over lent word views:

    analyze(cfg: ptr<b64,READ,space 2>, heap_view<IN_EXTENT>, memory,
            out: ptr<b64,RW,space 2>, heap_view<OUT_EXTENT>, memory) -> (the views)

Input words: block count n, entry, then per block its edge count and edge
targets in terminator order.  Output: ``out[0]`` status (0 accept, 1 reject
on a branch target >= n, 2 defer when the scratch would not fit), ``out[1]``
the words per dominator bitset W, ``out[2 : 2+n]`` the block order, then n
bitsets of W words.  Predecessor lists are built by a counting pass; the
dominator fixpoint starts from the full sets (the entry's own set excepted)
exactly as the bootstrap does, so its unique maximal solution is the same;
the walk visits successors in edge order with an explicit stack, matching
the bootstrap's order block for block.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import platform
import sys
import threading
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    Permission,
    SemanticObject,
    StoreReader,
    bits_type,
    heap_view_type,
    memory_effect_type,
    pointer_type,
    verify_store,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_cfg_analysis.xax"
IN_EXTENT = 1 << 20
OUT_EXTENT = 1 << 22
IN_WORDS, OUT_WORDS = IN_EXTENT // 8, OUT_EXTENT // 8
ACCEPT, REJECT, DEFER = 0, 1, 2

B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
MEM = memory_effect_type()
IN_POINTER = pointer_type(B64, Permission.READ, 8, space=2)
OUT_POINTER = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
IN_VIEW, OUT_VIEW = heap_view_type(IN_EXTENT), heap_view_type(OUT_EXTENT)
STATE = (IN_VIEW, MEM, OUT_VIEW, MEM)


class _Builder:
    def __init__(self) -> None:
        self.g = GraphBuilder()
        entry = self.g.block(IN_POINTER, IN_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
        self.inp, in_view, in_mem, self.out, out_view, out_mem = entry.params
        self.cur, self.state = entry, (in_view, in_mem, out_view, out_mem)
        self.reject_block, self.defer_block = self.g.block(*STATE), self.g.block(*STATE)

    def c(self, value):
        return self.cur.const(B64, value)

    def op(self, operation, x, y):
        return self.cur.op1(operation, (x, self.c(y) if isinstance(y, int) else y), B64)

    def add(self, x, y):
        return self.op(Operation.ADD_WRAP, x, y)

    def sub(self, x, y):
        return self.op(Operation.SUB_WRAP, x, y)

    def mul(self, x, y):
        return self.op(Operation.MUL_WRAP, x, y)

    def cmp(self, kind, x, y):
        return self.cur.op1(Operation.INT_COMPARE, (x, self.c(y) if isinstance(y, int) else y), B1, attributes=(kind,))

    def _offset(self, index):
        return self.cur.op1(Operation.INT_TRUNCATE, (self.mul(index, 8),), B32)

    def read(self, index):
        in_view, in_mem, out_view, out_mem = self.state
        self.check(self.cmp(IntCompare.ULT, index, IN_WORDS), self.reject_block)
        in_view, in_mem, out_view, out_mem = self.state
        value, in_mem = self.cur.op(Operation.CHECKED_LOAD_BITS_LE, (self.inp, self._offset(index), in_mem), (B64, MEM), attributes=(8, 1))
        self.state = (in_view, in_mem, out_view, out_mem)
        return value

    def get(self, index):
        in_view, in_mem, out_view, out_mem = self.state
        value, out_mem = self.cur.op(Operation.CHECKED_LOAD_BITS_LE, (self.out, self._offset(index), out_mem), (B64, MEM), attributes=(8, 1))
        self.state = (in_view, in_mem, out_view, out_mem)
        return value

    def put(self, index, value):
        in_view, in_mem, out_view, out_mem = self.state
        out_mem = self.cur.op1(Operation.CHECKED_STORE_BITS_LE, (self.out, self._offset(index), self.c(value) if isinstance(value, int) else value, out_mem), MEM, attributes=(8, 1))
        self.state = (in_view, in_mem, out_view, out_mem)

    def check(self, condition, failure=None):
        following = self.g.block(*STATE)
        self.cur.cbr(condition, following, self.state, failure or self.reject_block, self.state)
        self.cur, self.state = following, tuple(following.params)

    def enter(self, block, leading=0):
        self.cur, self.state = block, tuple(block.params[leading:])

    def loop(self, values, condition, body):
        """``while condition(values): values = body(values)``; returns the exit values."""
        header = self.g.block(*(B64,) * len(values), *STATE)
        self.cur.br(header, *values, *self.state)
        self.enter(header, len(values))
        current = header.params[: len(values)]
        inside, done = self.g.block(*STATE), self.g.block(*STATE)
        self.cur.cbr(condition(current), inside, self.state, done, self.state)
        self.enter(inside)
        following = body(current)
        self.cur.br(header, *following, *self.state)
        self.enter(done)
        return current

    def for_range(self, start, stop, body, carried=()):
        """``for i in range(start, stop): carried = body(i, carried)``; returns carried."""
        values = self.loop((start, *carried), lambda v: self.cmp(IntCompare.ULT, v[0], stop), lambda v: (self.add(v[0], 1), *body(v[0], tuple(v[1:]))))
        return tuple(values[1:])

    def select(self, condition, if_true, if_false):
        flag = self.cur.op1(Operation.INT_ZERO_EXTEND, (condition,), B64)
        return self.add(if_false, self.mul(flag, self.sub(if_true, if_false)))


def build_cfg_program() -> tuple[StoreReader, SemanticObject]:
    b = _Builder()
    n, entry = b.read(b.c(0)), b.read(b.c(1))
    b.check(b.cmp(IntCompare.ULT, entry, n), b.reject_block)  # the parser already proved this
    b.check(b.cmp(IntCompare.ULE, n, 1 << 16), b.defer_block)
    words = b.op(Operation.UDIV, b.add(n, 63), 64)
    # Layout of ``out``.
    order = b.c(2)
    dom = b.add(order, n)
    succ_start = b.add(dom, b.mul(n, words))
    succ_count, pred_count, pred_start, visited = (b.add(succ_start, b.mul(n, k)) for k in (1, 2, 3, 4))
    power = b.add(succ_start, b.mul(n, 5))          # 64 powers of two
    stack = b.add(power, 64)                          # (block, cursor) pairs, 2n
    tmp = b.add(stack, b.mul(n, 2))                   # one bitset, W words
    preds = b.add(tmp, words)                         # edge-total words (at most IN_WORDS)
    # The whole layout must fit before anything is written.
    b.check(b.cmp(IntCompare.ULE, b.add(preds, IN_WORDS), OUT_WORDS), b.defer_block)
    # Pass 1: edge lists (each target < n), with their start and count.
    b.for_range(b.c(0), n, lambda block, carried: _edge_list(b, n, block, carried, succ_start, succ_count), (b.c(2), b.c(0)))
    # Powers of two.
    b.for_range(b.c(0), b.c(64), lambda k, carried: _power(b, power, k, carried), (b.c(1),))
    # Predecessors by counting sort.
    b.for_range(b.c(0), n, lambda i, c: (b.put(b.add(pred_count, i), 0), b.put(b.add(visited, i), 0)) and (), ())
    b.for_range(b.c(0), n, lambda p, c: _each_edge(b, p, succ_start, succ_count, lambda t: b.put(b.add(pred_count, t), b.add(b.get(b.add(pred_count, t)), 1))), ())
    b.for_range(b.c(0), n, lambda t, carried: _prefix(b, t, carried, pred_count, pred_start), (b.c(0),))
    b.for_range(b.c(0), n, lambda p, c: _each_edge(b, p, succ_start, succ_count, lambda t: _place(b, p, t, pred_count, pred_start, preds)), ())
    # Dominators: full sets for every block but the entry, which is {entry}.
    last_bits = b.op(Operation.UREM, n, 64)
    last_mask = b.select(b.cmp(IntCompare.EQ, last_bits, 0), b.c((1 << 64) - 1), b.sub(b.get(b.add(power, last_bits)), 1))
    full = lambda w: b.select(b.cmp(IntCompare.EQ, w, b.sub(words, 1)), last_mask, b.c((1 << 64) - 1))
    b.for_range(b.c(0), n, lambda block, c: b.for_range(b.c(0), words, lambda w, c2: (b.put(b.add(dom, b.add(b.mul(block, words), w)), full(w)),) and (), ()) or (), ())
    b.for_range(b.c(0), words, lambda w, c: (b.put(b.add(dom, b.add(b.mul(entry, words), w)), 0),) and (), ())
    _set_bit(b, dom, entry, entry, words, power)
    b.loop((b.c(1),), lambda v: b.cmp(IntCompare.NE, v[0], 0), lambda v: (_dominator_pass(b, n, entry, words, dom, tmp, power, pred_count, pred_start, preds),))
    # Reverse postorder of a depth-first walk from the entry; unreached blocks after.
    b.put(stack, entry)
    b.put(b.add(stack, 1), 0)
    b.put(b.add(visited, entry), 1)
    (_depth, finished) = b.loop((b.c(1), b.c(0)), lambda v: b.cmp(IntCompare.NE, v[0], 0), lambda v: _walk_step(b, v[0], v[1], stack, visited, succ_start, succ_count, order))
    b.for_range(b.c(0), b.op(Operation.UDIV, finished, 2), lambda i, c: _swap(b, order, i, b.sub(b.sub(finished, i), 1)) or (), ())
    b.for_range(b.c(0), n, lambda block, carried: _append_unvisited(b, block, carried, visited, order, tmp), (finished,))
    b.put(b.c(1), words)
    b.put(b.c(0), ACCEPT)
    in_view, in_mem, out_view, out_mem = b.state
    b.cur.ret(b.inp, in_view, in_mem, b.out, out_view, out_mem)
    for failure, status in ((b.reject_block, REJECT), (b.defer_block, DEFER)):
        b.enter(failure)
        b.put(b.c(0), status)
        in_view, in_mem, out_view, out_mem = b.state
        b.cur.ret(b.inp, in_view, in_mem, b.out, out_view, out_mem)
    triples = (IN_POINTER, IN_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    function = b.g.function(triples, triples)
    return program_store(function, x86_64_linux_exec_target(), tuple(b.g.objects.values())), function


def _edge_list(b, n, block, carried, succ_start, succ_count):
    position, total = carried
    count = b.read(position)
    b.put(b.add(succ_start, block), b.add(position, 1))
    b.put(b.add(succ_count, block), count)
    b.for_range(b.c(0), count, lambda e, c: b.check(b.cmp(IntCompare.ULT, b.read(b.add(b.add(position, 1), e)), n), b.reject_block) or (), ())
    return b.add(b.add(position, 1), count), b.add(total, count)


def _power(b, power, k, carried):
    (value,) = carried
    b.put(b.add(power, k), value)
    return (b.mul(value, 2),)


def _each_edge(b, block, succ_start, succ_count, action):
    start, count = b.get(b.add(succ_start, block)), b.get(b.add(succ_count, block))
    b.for_range(b.c(0), count, lambda e, c: action(b.read(b.add(start, e))) or (), ())
    return ()


def _prefix(b, t, carried, pred_count, pred_start):
    (running,) = carried
    b.put(b.add(pred_start, t), running)
    count = b.get(b.add(pred_count, t))
    b.put(b.add(pred_count, t), 0)  # reused as the fill cursor
    return (b.add(running, count),)


def _place(b, p, t, pred_count, pred_start, preds):
    filled = b.get(b.add(pred_count, t))
    b.put(b.add(preds, b.add(b.get(b.add(pred_start, t)), filled)), p)
    b.put(b.add(pred_count, t), b.add(filled, 1))


def _set_bit(b, base, block, bit, words, power):
    index = b.add(base, b.add(b.mul(block, words), b.op(Operation.UDIV, bit, 64)))
    b.put(index, b.op(Operation.BIT_OR, b.get(index), b.get(b.add(power, b.op(Operation.UREM, bit, 64)))))


def _dominator_pass(b, n, entry, words, dom, tmp, power, pred_count, pred_start, preds):
    def block_step(block, carried):
        (changed,) = carried
        skip = b.cmp(IntCompare.EQ, block, entry)
        count = b.get(b.add(pred_count, block))
        start = b.get(b.add(pred_start, block))
        has_preds = b.cmp(IntCompare.NE, count, 0)
        b.for_range(b.c(0), words, lambda w, c: (b.put(b.add(tmp, w), b.select(has_preds, b.c((1 << 64) - 1), b.c(0))),) and (), ())
        def intersect(k, c):
            p = b.get(b.add(preds, b.add(start, k)))
            b.for_range(b.c(0), words, lambda w, c2: (b.put(b.add(tmp, w), b.op(Operation.BIT_AND, b.get(b.add(tmp, w)), b.get(b.add(dom, b.add(b.mul(p, words), w))))),) and (), ())
            return ()
        b.for_range(b.c(0), count, intersect, ())
        _set_bit(b, tmp, b.c(0), block, words, power)
        def compare(w, c):
            (different,) = c
            here = b.add(dom, b.add(b.mul(block, words), w))
            return (b.op(Operation.BIT_OR, different, b.cur.op1(Operation.INT_ZERO_EXTEND, (b.cmp(IntCompare.NE, b.get(here), b.get(b.add(tmp, w))),), B64)),)
        (different,) = b.for_range(b.c(0), words, compare, (b.c(0),))
        update = b.mul(different, b.cur.op1(Operation.INT_ZERO_EXTEND, (b.cmp(IntCompare.NE, block, entry),), B64))
        def copy(w, c):
            here = b.add(dom, b.add(b.mul(block, words), w))
            b.put(here, b.select(b.cmp(IntCompare.NE, update, 0), b.get(b.add(tmp, w)), b.get(here)))
            return ()
        b.for_range(b.c(0), words, copy, ())
        del skip
        return (b.op(Operation.BIT_OR, changed, update),)
    (changed,) = b.for_range(b.c(0), n, block_step, (b.c(0),))
    return changed


def _walk_step(b, depth, finished, stack, visited, succ_start, succ_count, order):
    top = b.add(stack, b.mul(b.sub(depth, 1), 2))
    current, cursor = b.get(top), b.get(b.add(top, 1))
    more = b.cmp(IntCompare.ULT, cursor, b.get(b.add(succ_count, current)))
    descend, finish, joined = (b.g.block(B64, B64, *STATE) for _ in range(3))
    b.cur.cbr(more, descend, (depth, finished, *b.state), finish, (depth, finished, *b.state))
    b.enter(descend, 2)
    b.put(b.add(top, 1), b.add(cursor, 1))
    successor = b.read(b.add(b.get(b.add(succ_start, current)), cursor))
    fresh = b.cmp(IntCompare.EQ, b.get(b.add(visited, successor)), 0)
    push, skip = b.g.block(*STATE), b.g.block(*STATE)
    b.cur.cbr(fresh, push, b.state, skip, b.state)
    b.enter(push)
    b.put(b.add(visited, successor), 1)
    b.put(b.add(top, 2), successor)
    b.put(b.add(top, 3), 0)
    b.cur.br(joined, b.add(depth, 1), finished, *b.state)
    b.enter(skip)
    b.cur.br(joined, depth, finished, *b.state)
    b.enter(finish, 2)
    b.put(b.add(order, finished), current)
    b.cur.br(joined, b.sub(depth, 1), b.add(finished, 1), *b.state)
    b.enter(joined, 2)
    return joined.params[0], joined.params[1]


def _swap(b, order, i, j):
    left, right = b.get(b.add(order, i)), b.get(b.add(order, j))
    b.put(b.add(order, i), right)
    b.put(b.add(order, j), left)


def _append_unvisited(b, block, carried, visited, order, scratch):
    (count,) = carried
    unvisited = b.cmp(IntCompare.EQ, b.get(b.add(visited, block)), 0)
    flag = b.cur.op1(Operation.INT_ZERO_EXTEND, (unvisited,), B64)
    # Branch-free: an unvisited block goes to order[count], a visited one to a scratch word.
    b.put(b.select(unvisited, b.add(order, count), scratch), block)
    return (b.add(count, flag),)


def load_cfg_program() -> tuple[StoreReader, SemanticObject]:
    reader = StoreReader(STORE_PATH.read_bytes())
    verify_store(reader)
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_cfg_store() -> bytes:
    import xax_compiler

    building = xax_compiler._CFG_BUILDING
    xax_compiler._CFG_BUILDING = True
    try:
        reader, _function = build_cfg_program()
        STORE_PATH.write_bytes(reader.data)
    finally:
        xax_compiler._CFG_BUILDING = building
    return reader.data


class NativeCfg:
    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK, compile_native

        reader, function = load_cfg_program()
        target = next(item for item in reader.objects() if item.kind == Kind.TARGET)
        image = compile_native(reader, function.cid, target.cid)
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + image.code
        self._mapping = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self._mapping.write(code)
        base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + image.entry_offset
        self.code_size = len(image.code)
        self._in = (ctypes.c_uint64 * IN_WORDS)()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def analyze(self, entry: int, successors: list[list[int]]):
        """``(status, order, dominator sets)`` for blocks with these edge targets."""
        words = [len(successors), entry]
        for targets in successors:
            words.append(len(targets))
            words.extend(targets)
        if len(words) > IN_WORDS or any(word >= 1 << 63 for word in words):
            return DEFER, None, None
        with self._lock:
            self._in[: len(words)] = words
            slots = self._slots
            slots[0], slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            status = self._out[0]
            if status != ACCEPT:
                return status, None, None
            n, width = len(successors), self._out[1]
            order = list(self._out[2 : 2 + n])
            flat = self._out[2 + n : 2 + n + n * width]
        dominators = []
        for block in range(n):
            bits = 0
            for index in range(width):
                bits |= flat[block * width + index] << (64 * index)
            dominators.append({index for index in range(n) if bits >> index & 1})
        return status, order, dominators


def native_cfg_usable() -> bool:
    return (
        sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
        and os.environ.get("XAX_CFG_PYTHON") != "1" and STORE_PATH.exists()
    )
