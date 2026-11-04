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
the words per dominator bitset W, ``out[2]`` whether every value use is valid
(S3e), ``out[3 : 3+n]`` the block order, then n bitsets of W words.  After the
edges come each block's parameter count, node count, and per-node result
counts, then the uses: (use block, use node position, tag, value block, index,
result).  A use is valid exactly when the bootstrap ``value_type`` would accept
it: the block exists, the index (and result) exist, a node result precedes its
use in the same block, and the defining block dominates the use's block.  Predecessor lists are built by a counting pass; the
dominator fixpoint starts from the full sets (the entry's own set excepted)
exactly as the bootstrap does, so its unique maximal solution is the same;
the walk visits successors in edge order with an explicit stack, matching
the bootstrap's order block for block.
"""

from __future__ import annotations

import ctypes
import threading

from xax_compiler import (
    IntCompare, Kind, Operation, Permission, SemanticObject, StoreReader, bits_type, heap_view_type, memory_effect_type, pointer_type)
from xax_graph_builder import GraphBuilder

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_cfg_analysis.xax"
IN_EXTENT = 1 << 26  # S15e.6i.2a (ADR-358): 8M input words (was 2M), so the driver's own function can grow
OUT_EXTENT = 1 << 27  # its input words and the tables after them
IN_WORDS, OUT_WORDS = IN_EXTENT // 8, OUT_EXTENT // 8
ACCEPT, REJECT, DEFER = 0, 1, 2

B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
MEM = memory_effect_type()
IN_POINTER = pointer_type(B64, Permission.READ, 8, space=2)
OUT_POINTER = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
IN_VIEW, OUT_VIEW = heap_view_type(IN_EXTENT), heap_view_type(OUT_EXTENT)
STATE = (IN_VIEW, MEM, OUT_VIEW, MEM)


class _Builder:
    def __init__(self, in_extent: int = IN_EXTENT, out_extent: int = OUT_EXTENT) -> None:
        # Other self-hosted programs reuse this builder with their own view extents.
        self.in_words = in_extent // 8
        self.in_pointer, self.out_pointer = IN_POINTER, OUT_POINTER
        self.in_view, self.out_view = heap_view_type(in_extent), heap_view_type(out_extent)
        self.state_types = (self.in_view, MEM, self.out_view, MEM)
        self.g = GraphBuilder()
        entry = self.g.block(self.in_pointer, self.in_view, MEM, self.out_pointer, self.out_view, MEM)
        self.inp, in_view, in_mem, self.out, out_view, out_mem = entry.params
        self.cur, self.state = entry, (in_view, in_mem, out_view, out_mem)
        self.reject_block, self.defer_block = self.g.block(*self.state_types), self.g.block(*self.state_types)

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
        self.check(self.cmp(IntCompare.ULT, index, self.in_words), self.reject_block)
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
        following = self.g.block(*self.state_types)
        self.cur.cbr(condition, following, self.state, failure or self.reject_block, self.state)
        self.cur, self.state = following, tuple(following.params)

    def enter(self, block, leading=0):
        self.cur, self.state = block, tuple(block.params[leading:])

    def loop(self, values, condition, body):
        """``while condition(values): values = body(values)``; returns the exit values."""
        header = self.g.block(*(B64,) * len(values), *self.state_types)
        self.cur.br(header, *values, *self.state)
        self.enter(header, len(values))
        current = header.params[: len(values)]
        inside, done = self.g.block(*self.state_types), self.g.block(*self.state_types)
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


def load_cfg_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "cfg")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


class NativeCfg:
    def __init__(self) -> None:
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = host_image(*load_cfg_program(), "cfg")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + machine_code
        from xax_native import executable_mapping, zeroed_array

        self._mapping, base = executable_mapping(code)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self.code_size = len(machine_code)
        self._in = zeroed_array(ctypes.c_uint64, IN_WORDS)
        self._out = zeroed_array(ctypes.c_uint64, OUT_WORDS)
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def analyze(self, entry: int, successors: list[list[int]], values=None):
        """``(status, order, dominator sets, uses valid)`` for blocks with these edge targets.

        ``values`` is ``(per-block (parameter count, result counts per node), uses)``
        where each use is (use block, use node position, tag, block, index, result).
        """
        self.rejected_target, self.use_codes = None, []
        words = [len(successors), entry]
        for targets in successors:
            words.append(len(targets))
            words.extend(targets)
        tables, uses = values or ([(0, ())] * len(successors), ())
        for parameter_count, result_counts in tables:
            words += [parameter_count, len(result_counts), *result_counts]
        words.append(len(uses))
        for use in uses:
            words.extend(use)
        if len(words) > IN_WORDS or any(word >= 1 << 63 for word in words):
            return DEFER, None, None, False
        with self._lock:
            self._in[: len(words)] = words
            slots = self._slots
            slots[0], slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            status = self._out[0]
            self.rejected_target = self._out[1] if status == REJECT else None  # S8: the first branch target out of range
            if status != ACCEPT:
                return status, None, None, False
            n, width, valid = len(successors), self._out[1], bool(self._out[2])
            order = list(self._out[3 : 3 + n])
            flat = self._out[3 + n : 3 + n + n * width]
            # S8 (ADR-251): each use's outcome, after the layout the frozen program fixes.
            codes = 3 + n + n * width + 5 * n + 64 + 2 * n + width + IN_WORDS + 3 * n
            self.use_codes = list(self._out[codes : codes + len(uses)])
        dominators = []
        for block in range(n):
            bits = 0
            for index in range(width):
                bits |= flat[block * width + index] << (64 * index)
            dominators.append({index for index in range(n) if bits >> index & 1})
        return status, order, dominators, valid


def native_cfg_usable() -> bool:
    import xax_native

    return xax_native.usable("cfg", STORE_PATH, "XAX_CFG_PYTHON")
