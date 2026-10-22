"""The carrier reader: parse ``xax-construct-v1`` JSON and re-emit it canonically (step 3).

This is the decoder's front half.  It turns the carrier bytes into a tree the construct path can
walk -- kind, byte span, first child, next sibling -- and proves the tree is right by writing it
back out in canonical form.  The oracle is exact: for every carrier in XAX-MCP,

    reader.exe <carrier> <output>

must produce ``json.dumps(json.loads(carrier), separators=(",", ":"))`` byte for byte.  Both
committed carriers are already in that form, so the check also proves no byte was lost or invented.

Bounded on purpose -- the carriers were measured, and anything outside the measured class is
refused with a code rather than approximated:

* integers only; a fraction or exponent is refused (no honest ``repr(float)`` here),
* ASCII only; a raw byte >= 0x80 is refused (no UTF-8 decoder here),
* no escapes; a backslash in a string is refused (no ``\\uXXXX`` decoder here),
* member order is preserved; this reader does not sort, so a carrier whose keys are not already in
  sorted order is caught by the oracle (which uses ``sort_keys=True``) rather than normalized --
  step 3b adds the sort, and no committed carrier needs it,
* at most 262 144 nodes, depth 32, 4 MiB in, 4 MiB out.

Each of those limits is a *refusal*, so a carrier this reader accepts is one it understood
completely.  They are the list step 3b closes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import xax_compiler as X
from xax_compiler import IntCompare, Operation, foreign_function_symbol, heap_view_type, x86_64_windows_pe_target
from xax_platform import win32_kernel32_api, win32_stdio_api
from xax_structured import B8, B32, B64, Proc

EXTENT = 16 << 20
COMMAND_CAP = 32768
PATH_ONE, PATH_TWO, PATH_THREE, PATH_CAP = 0x8000, 0x9000, 0xA000, 4096
IN, IN_CAP = 0x10000, 4 << 20
OUT, OUT_CAP = 0x410000, 4 << 20
NODES, NODE_CAP = 0x810000, 1 << 18
KIND = NODES
START = NODES + 4 * NODE_CAP
END = NODES + 8 * NODE_CAP
FIRST = NODES + 12 * NODE_CAP
NEXT = NODES + 16 * NODE_CAP
SCRATCH = NODES + 20 * NODE_CAP
NS = 0xE00000  # the embedded platform namespace blob (step 4)
SCRATCH_CAP = 0x1000
PNODE, PPHASE, PLAST, PMEMBER = SCRATCH, SCRATCH + 128, SCRATCH + 256, SCRATCH + 384
ENODE, ECURSOR, EFIRST = SCRATCH + 512, SCRATCH + 640, SCRATCH + 768
CAP = 32

SPACE, TAB, LF, CR = 32, 9, 10, 13
QUOTE, BACKSLASH, COMMA, COLON = 34, 92, 44, 58
LBRACE, RBRACE, LBRACKET, RBRACKET = 123, 125, 91, 93
MINUS, DOT, ZERO, NINE = 45, 46, 48, 57
UPPER_E, LOWER_E = 69, 101

OBJECT, ARRAY, STRING, INTEGER, TRUE, FALSE, NULL, MEMBER = 0, 1, 2, 3, 4, 5, 6, 7
OBJ_KEY, OBJ_COLON, OBJ_VALUE, OBJ_NEXT, ARR_VALUE, ARR_NEXT, OBJ_KEY_STRICT, ARR_VALUE_STRICT = 0, 1, 2, 3, 4, 5, 6, 7

OPEN_READ, OPEN_WRITE, CREATE_MODE = 0x8000, 0x8301, 0x0180
EXIT_BAD_OPEN_IN, EXIT_BAD_OPEN_OUT, EXIT_READ, EXIT_TOO_LARGE = 2, 3, 4, 5
EXIT_SHORT_WRITE, EXIT_TRAILING, EXIT_SYNTAX, EXIT_OVERFLOW = 6, 7, 8, 9
EXIT_NO_STORE = 10


def _accessors(p, declarations, pointer_type, view_type, proc_type, fs_type, mem_type, extra_views=()):
    """The byte, node and output accessors of one function, bound to its ``proc``.

    The reader's front half and a resolver's second function share this code; every accessor reads and
    writes the named registers of the ``proc`` it is built for, so nothing is shared at run time."""

    def c32(value):
        return p.const(value, B32)

    def add(left, right):
        return p.bin(Operation.ADD_WRAP, left, right, B32)

    def sub(left, right):
        return p.bin(Operation.SUB_WRAP, left, right, B32)

    def mul(left, right):
        return p.bin(Operation.MUL_WRAP, left, right, B32)

    def at(offset):
        return p.op1(Operation.ADDRESS_OFFSET, (p["vp"],), pointer_type, attributes=(offset,))

    def ld8(offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["base"], offset, p["mem"]), (B8, mem_type),
                             attributes=(1, 1))
        p["mem"] = memory
        return value

    def st8(offset, value):
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE, (p["base"], offset, value, p["mem"]), (mem_type,),
                         attributes=(1, 1))
        p["mem"] = memory

    def ld32(offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["base"], offset, p["mem"]), (B32, mem_type),
                             attributes=(4, 1))
        p["mem"] = memory
        return value

    def st32(offset, value):
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE, (p["base"], offset, value, p["mem"]), (mem_type,),
                         attributes=(4, 1))
        p["mem"] = memory

    def byte(offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["in"], offset, p["mem"]), (B8, mem_type),
                             attributes=(1, 1))
        p["mem"] = memory
        return p.widen(value, B32)

    def store_out(offset, value):
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE, (p["outp"], offset, value, p["mem"]), (mem_type,),
                         attributes=(1, 1))
        p["mem"] = memory

    def put_dyn(value):
        """Write a computed ``b32`` as one byte."""
        store_out(p["out"], p.op1(Operation.INT_TRUNCATE, (value,), B8))
        p["out"] = add(p["out"], c32(1))
        fail_if(p.cmp(IntCompare.UGE, p["out"], c32(OUT_CAP), B32), EXIT_OVERFLOW)

    def st64(offset, value):
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE, (p["base"], offset, value, p["mem"]), (mem_type,),
                         attributes=(8, 1))
        p["mem"] = memory

    def ld64(offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["base"], offset, p["mem"]), (B64, mem_type),
                             attributes=(8, 1))
        p["mem"] = memory
        return value

    def eq(value, constant):
        return p.cmp(IntCompare.EQ, value, c32(constant), B32)

    def ne(value, constant):
        return p.cmp(IntCompare.NE, value, c32(constant), B32)

    def lt(left, right):
        return p.cmp(IntCompare.ULT, left, right, B32)

    def exit_with(code):
        p["mem"] = p.op(Operation.CALL_FOREIGN,
                        (p["vp"], p.const(0, B64), c32(0x8000), p["vv"], p["mem"]), (B32, mem_type),
                        entity=declarations["free"])[1]
        # every view this process lent is a resource: it is released here, in the order it was taken
        for pointer_name, token_name, memory_name, extent, declaration in extra_views:
            p[memory_name] = p.op(Operation.CALL_FOREIGN,
                                  (p[pointer_name], p.const(extent, B64), c32(0x8000), p[token_name],
                                   p[memory_name]), (B32, mem_type), entity=declaration)[1]
        p["proc"] = p.op1(Operation.CALL_FOREIGN, (code, p["proc"]), proc_type, entity=declarations["exit"])
        p.ret(code, p["proc"], p["fs"], p["mem"],
              *(p[memory] for _pointer, _token, memory, _extent, _declaration in extra_views))

    def guard(work):
        p.if_(eq(p["code"], 0), lambda _p: work())

    def fail_if(condition, code):
        # ``code = code + (code == 0 && condition ? code : 0)``.  A branch here would add a block at every
        # check site, and a function's verifier work grows with its block count: the first failure wins
        # either way, and no later check can overwrite it.
        p["code"] = add(p["code"], mul(p.widen(p.all_of(eq(p["code"], 0), condition)), c32(code)))

    def put(node, field, value):
        st32(add(field, mul(node, c32(4))), value)

    def get(node, field):
        return ld32(add(field, mul(node, c32(4))))

    def frame_slot(slot, field):
        return add(field, mul(slot, c32(4)))

    def put_out(value):
        store_out(p["out"], p.const(value, B8))
        p["out"] = add(p["out"], c32(1))
        fail_if(p.cmp(IntCompare.UGE, p["out"], c32(OUT_CAP), B32), EXIT_OVERFLOW)

    def raw_at(pointer, offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, offset, p["mem"]), (B8, mem_type),
                             attributes=(1, 1))
        p["mem"] = memory
        return value

    return {
        "p": p, "c32": c32, "add": add, "sub": sub, "mul": mul, "at": at,
        "ld8": ld8, "ld32": ld32, "st8": st8, "st32": st32, "st64": st64, "ld64": ld64,
        "byte": byte, "load_out": store_out, "store_out": store_out, "in_byte": raw_at, "raw_at": raw_at,
        "out_byte": put_out, "put_out": put_out, "out_dyn": put_dyn, "put_dyn": put_dyn,
        "fail": fail_if, "fail_if": fail_if, "guard": guard, "eq": eq, "ne": ne, "lt": lt, "cmp": p.cmp,
        "exit_with": exit_with, "put": put, "get": get, "frame_slot": frame_slot,
    }


def _imports(api, pointer):
    abi = b"win64-c"
    process, filesystem, memory = api.process_effect, api.filesystem_effect, api.memory_effect
    return {
        "command_line": foreign_function_symbol(b"kernel32.dll", b"GetCommandLineA", (process,), (B64, process), abi=abi),
        "copy": foreign_function_symbol(b"kernel32.dll", b"lstrcpynA", (pointer, B64, B32, memory), (B64, memory), abi=abi),
        "open": foreign_function_symbol(b"msvcrt.dll", b"_open", (pointer, B32, B32, filesystem), (B32, filesystem), abi=abi),
        "read": foreign_function_symbol(b"msvcrt.dll", b"_read", (B32, pointer, B32, filesystem, memory),
                                        (B32, filesystem, memory), abi=abi),
        "write": foreign_function_symbol(b"msvcrt.dll", b"_write", (B32, pointer, B32, filesystem, memory),
                                         (B32, filesystem, memory), abi=abi),
        "close": foreign_function_symbol(b"msvcrt.dll", b"_close", (B32, filesystem), (B32, filesystem), abi=abi),
        "exit": api.exit_process,
        "allocate": api.virtual_alloc,
    }


def build_main(api, stdio, on_tree=None, view_alignment=1, store_writer=None, store_only=False):
    """``main(proc, fs, mem) -> (b32, proc, fs, mem)``: normalize a carrier.

    With ``on_tree`` the parsed tree is handed to that callback instead of being re-emitted; it receives
    an environment of the node accessors, the byte helpers and the output writer.  ``view_alignment`` is
    the alignment the byte view is lent with; a resolver that hashes inside the view asks for four, so a
    word-aligned scratch area can be addressed.

    With ``store_writer`` the same callback also gets three more views -- the writer's batch, the store it
    writes and its hash scratch -- each with its own memory proof, and the process gains a third path: the
    callback leaves a store length in ``store_len`` and this front half writes ``written[0..store_len]``
    there.  The writer itself is called by the callback; this half only owns the buffers and the file."""
    proc_type, fs_type, mem_type = api.process_effect, api.filesystem_effect, api.memory_effect
    pointer_type, view_type = stdio.bytes_rw, heap_view_type(EXTENT)
    declarations = _imports(api, pointer_type)
    declarations["free"] = api.virtual_free_view(view_type, pointer_type)
    buffers = () if store_writer is None else tuple(store_writer["buffers"])
    parameters = [("proc", proc_type), ("fs", fs_type), ("mem", mem_type)]
    parameters += [(f"mem_{name}", mem_type) for name, _pointer, _view, _extent, _alignment in buffers]
    p = Proc(parameters)

    A = _accessors(p, declarations, pointer_type, view_type, proc_type, fs_type, mem_type,
                   extra_views=tuple((f"{name}_p", f"{name}_v", f"{name}_m", extent,
                                      api.virtual_free_view(buffer_view, buffer_pointer))
                                     for name, buffer_pointer, buffer_view, extent, _alignment in buffers))
    (c32, add, sub, mul, at, ld8, st8, ld32, st32, byte, store_out, put_dyn, st64, eq, ne, lt,
     exit_with, guard, fail_if, put, get, frame_slot, put_out, raw_at) = (
        A[name] for name in ("c32", "add", "sub", "mul", "at", "ld8", "st8", "ld32", "st32", "byte",
                             "store_out", "put_dyn", "st64", "eq", "ne", "lt", "exit_with", "guard",
                             "fail_if", "put", "get", "frame_slot", "put_out", "raw_at"))

    block, owner, memory = p.op(
        Operation.CALL_FOREIGN, (p.const(0, B64), p.const(EXTENT, B64), c32(0x3000), c32(4), p["mem"]),
        (api.heap_ptr_rw, api.heap_resource, mem_type), entity=declarations["allocate"])
    p["mem"] = memory
    base, view, memory = p.op(Operation.HEAP_VIEW, (block, owner, p["mem"]), (pointer_type, view_type, mem_type),
                              attributes=(EXTENT, view_alignment))
    p["mem"] = memory
    p.let("vp", pointer_type, base)
    p.let("vv", view_type, view)
    p.let("base", pointer_type, at(0))
    p.let("in", pointer_type, at(IN))
    p.let("outp", pointer_type, at(OUT))

    for name, buffer_pointer, buffer_view, extent, alignment in buffers:
        block, owner, memory = p.op(
            Operation.CALL_FOREIGN,
            (p.const(0, B64), p.const(extent, B64), c32(0x3000), c32(4), p[f"mem_{name}"]),
            (api.heap_ptr_rw, api.heap_resource, mem_type), entity=declarations["allocate"])
        base, view, memory = p.op(Operation.HEAP_VIEW, (block, owner, memory),
                                  (buffer_pointer, buffer_view, mem_type), attributes=(extent, alignment))
        p.drop(f"mem_{name}")
        p.let(f"{name}_p", buffer_pointer, base)
        p.let(f"{name}_v", buffer_view, view)
        p.let(f"{name}_m", mem_type, memory)

    line, process = p.op(Operation.CALL_FOREIGN, (p["proc"],), (B64, proc_type), entity=declarations["command_line"])
    p["proc"] = process
    _, memory = p.op(Operation.CALL_FOREIGN, (at(0), line, c32(COMMAND_CAP), p["mem"]), (B64, mem_type),
                     entity=declarations["copy"])
    p["mem"] = memory

    for name in ("code", "i", "n", "byte", "fd", "got", "written", "q", "depth", "root", "nodes", "scan",
                 "value", "member", "out", "emit", "frame", "slot", "child", "kind", "a", "b", "t",
                 "store_len", "have_three"):
        p.let(name, B32, c32(0))
    p["nodes"] = c32(1)   # node 0 is "none"

    # -- argv -------------------------------------------------------------------------------------------
    def advance():
        p["i"] = add(p["i"], c32(1))

    def fetch():
        p["byte"] = p.widen(ld8(p["i"]), B32)

    def live():
        return p.all_of(lt(p["i"], c32(COMMAND_CAP)), ne(p["byte"], 0))

    def separated():
        return p.all_of(live(), eq(p["byte"], SPACE))

    def word(limit):
        return p.all_of(live(), ne(p["byte"], SPACE), lt(p["n"], c32(limit)))

    def scan_word(condition):
        def check():
            fetch()
            return condition()
        p.while_(lambda _p: check(), lambda _p: advance())

    def copy_word(destination, limit):
        def body(_p):
            st8(add(c32(destination), p["n"]), ld8(p["i"]))
            p["n"] = add(p["n"], c32(1))
            advance()
        p.while_(lambda _p: (fetch(), word(limit))[1], body)
        st8(add(c32(destination), p["n"]), p.const(0, B8))
        p["n"] = c32(0)

    scan_word(separated)
    scan_word(lambda: p.all_of(live(), ne(p["byte"], SPACE)))
    scan_word(separated)
    copy_word(PATH_ONE, PATH_CAP - 1)
    scan_word(separated)
    copy_word(PATH_TWO, PATH_CAP - 1)
    scan_word(separated)
    if store_only:
        # the command form is ``construct <carrier> <store>``: argv[2] is the store, and there is no
        # listing path to consume or require
        p["have_three"] = c32(1)
        fail_if(ne(p["byte"], 0), EXIT_TRAILING)
    elif store_writer is None:
        fail_if(ne(p["byte"], 0), EXIT_TRAILING)
    else:
        def third_path(_p):
            p["have_three"] = c32(1)
            copy_word(PATH_THREE, PATH_CAP - 1)
            scan_word(separated)
            fail_if(ne(p["byte"], 0), EXIT_TRAILING)
        p.if_(ne(p["byte"], 0), third_path)

    # -- I/O --------------------------------------------------------------------------------------------
    def read_input():
        p["fd"], p["fs"] = p.op(Operation.CALL_FOREIGN, (at(PATH_ONE), c32(OPEN_READ), c32(0), p["fs"]),
                                (B32, fs_type), entity=declarations["open"])
        fail_if(p.cmp(IntCompare.SLT, p["fd"], c32(0), B32), EXIT_BAD_OPEN_IN)
        p["got"], p["fs"], p["mem"] = p.op(Operation.CALL_FOREIGN,
                                           (p["fd"], at(IN), c32(IN_CAP), p["fs"], p["mem"]),
                                           (B32, fs_type, mem_type), entity=declarations["read"])
        p["fs"] = p.op(Operation.CALL_FOREIGN, (p["fd"], p["fs"]), (B32, fs_type), entity=declarations["close"])[1]
        fail_if(p.cmp(IntCompare.SLT, p["got"], c32(1), B32), EXIT_READ)
        fail_if(p.cmp(IntCompare.UGE, p["got"], c32(IN_CAP), B32), EXIT_TOO_LARGE)

    # -- tree -------------------------------------------------------------------------------------------
    def new_node(kind_value, start, end):
        fail_if(p.cmp(IntCompare.UGE, p["nodes"], c32(NODE_CAP), B32), EXIT_OVERFLOW)
        node = p["nodes"]
        put(node, KIND, c32(kind_value))
        put(node, START, start)
        put(node, END, end)
        put(node, FIRST, c32(0))
        put(node, NEXT, c32(0))
        p["nodes"] = add(node, c32(1))
        return node

    def skip_space():
        def check():
            p["byte"] = byte(p["q"])
            return p.all_of(lt(p["q"], p["got"]),
                            p.any_of(eq(p["byte"], SPACE), eq(p["byte"], TAB), eq(p["byte"], LF), eq(p["byte"], CR)))

        def body(_p):
            p["q"] = add(p["q"], c32(1))
        p.while_(lambda _p: check(), body)

    def backslash_or_control():
        return p.any_of(eq(p["byte"], BACKSLASH), p.cmp(IntCompare.UGE, p["byte"], c32(0x80), B32),
                        p.cmp(IntCompare.ULT, p["byte"], c32(0x20), B32))

    def scan_string():
        """``q`` is on the opening quote; leaves the content span in a/b and moves ``q`` past the close."""
        p["q"] = add(p["q"], c32(1))
        p["a"] = p["q"]

        def check():
            p["byte"] = byte(p["q"])
            return p.all_of(lt(p["q"], p["got"]), ne(p["byte"], QUOTE))

        def body(_p):
            fail_if(backslash_or_control(), EXIT_SYNTAX)
            p["q"] = add(p["q"], c32(1))
        p.while_(lambda _p: check(), body)
        fail_if(p.cmp(IntCompare.UGE, p["q"], p["got"], B32), EXIT_SYNTAX)
        fail_if(ne(byte(p["q"]), QUOTE), EXIT_SYNTAX)
        p["b"] = p["q"]
        p["q"] = add(p["q"], c32(1))

    def digit_at(position):
        return p.all_of(p.cmp(IntCompare.UGE, byte(position), c32(ZERO), B32),
                        p.cmp(IntCompare.ULE, byte(position), c32(NINE), B32))

    def scan_number():
        p["a"] = p["q"]
        p.if_(eq(byte(p["q"]), MINUS), lambda _p: p.__setitem__("q", add(p["q"], c32(1))))
        fail_if(p.cmp(IntCompare.UGE, p["q"], c32(IN_CAP), B32), EXIT_SYNTAX)
        p["t"] = p["q"]

        def more():
            return p.all_of(lt(p["q"], p["got"]), digit_at(p["q"]))

        def body(_p):
            p["q"] = add(p["q"], c32(1))
        p.while_(lambda _p: more(), body)
        fail_if(p.cmp(IntCompare.EQ, p["t"], p["q"], B32), EXIT_SYNTAX)
        # no leading zero, no fraction, no exponent
        fail_if(p.all_of(eq(byte(p["t"]), ZERO), p.cmp(IntCompare.NE, add(p["t"], c32(1)), p["q"], B32)), EXIT_SYNTAX)
        fail_if(p.any_of(eq(byte(p["q"]), DOT), eq(byte(p["q"]), LOWER_E), eq(byte(p["q"]), UPPER_E)), EXIT_SYNTAX)
        p["b"] = p["q"]

    def parse_value():
        p["scan"] = c32(0)
        p["value"] = c32(0)
        skip_space()
        fail_if(p.cmp(IntCompare.UGE, p["q"], p["got"], B32), EXIT_SYNTAX)
        p["byte"] = byte(p["q"])
        brace, bracket, quote = eq(p["byte"], LBRACE), eq(p["byte"], LBRACKET), eq(p["byte"], QUOTE)
        number = p.any_of(eq(p["byte"], MINUS), digit_at(p["q"]))

        def open_object(_p):
            node = new_node(OBJECT, p["q"], c32(0))
            p["q"] = add(p["q"], c32(1))
            p["scan"] = c32(1)
            push(node, OBJ_KEY)

        def open_array(_p):
            node = new_node(ARRAY, p["q"], c32(0))
            p["q"] = add(p["q"], c32(1))
            p["scan"] = c32(1)
            push(node, ARR_VALUE)

        def take_string(_p):
            p["scan"] = c32(1)
            scan_string()
            p["value"] = new_node(STRING, p["a"], p["b"])

        def take_number(_p):
            p["scan"] = c32(1)
            scan_number()
            p["value"] = new_node(INTEGER, p["a"], p["b"])

        def take_literal(word, kind_value):
            def take(_p):
                for offset, character in enumerate(word):
                    fail_if(ne(byte(add(p["q"], c32(offset))), character), EXIT_SYNTAX)
                p["scan"] = c32(1)
                p["value"] = new_node(kind_value, p["q"], add(p["q"], c32(len(word))))
                p["q"] = add(p["q"], c32(len(word)))
            return take

        p.if_(brace, open_object)
        p.if_(bracket, open_array)
        p.if_(quote, take_string)
        p.if_(number, take_number)
        p.if_(eq(p["byte"], 116), take_literal(b"true", TRUE))
        p.if_(eq(p["byte"], 102), take_literal(b"false", FALSE))
        p.if_(eq(p["byte"], 110), take_literal(b"null", NULL))
        fail_if(eq(p["scan"], 0), EXIT_SYNTAX)

    def push(node, phase):
        slot = p["depth"]
        st32(frame_slot(slot, PNODE), node)
        st32(frame_slot(slot, PPHASE), c32(phase))
        st32(frame_slot(slot, PLAST), c32(0))
        st32(frame_slot(slot, PMEMBER), c32(0))
        p["depth"] = add(slot, c32(1))
        fail_if(p.cmp(IntCompare.UGE, p["depth"], c32(CAP), B32), EXIT_OVERFLOW)

    def attach(container, node):
        first = get(container, FIRST)
        p.if_(p.cmp(IntCompare.EQ, first, c32(0), B32), lambda _p: put(container, FIRST, node))
        p.if_(p.cmp(IntCompare.NE, first, c32(0), B32), lambda _p: put(p["slot"], NEXT, node))
        p["slot"] = node

    def attach_member(container, node):
        put(p["member"], FIRST, node)
        attach(container, p["member"])

    def link_child(slot, container, node):
        p["slot"] = ld32(frame_slot(slot, PLAST))
        attach(container, node)
        st32(frame_slot(slot, PLAST), p["slot"])

    def link_member(slot, container, node):
        p["slot"] = ld32(frame_slot(slot, PLAST))
        attach_member(container, node)
        st32(frame_slot(slot, PLAST), p["slot"])

    def finish_child(parent_slot, node):
        parent = ld32(frame_slot(parent_slot, PNODE))
        phase = ld32(frame_slot(parent_slot, PPHASE))
        p["member"] = ld32(frame_slot(parent_slot, PMEMBER))
        is_member = p.cmp(IntCompare.EQ, phase, c32(OBJ_NEXT), B32)
        p.if_(is_member, lambda _p: link_member(parent_slot, parent, node),
              lambda _p: link_child(parent_slot, parent, node))

    def close(node):
        put(node, END, p["q"])
        p["depth"] = sub(p["depth"], c32(1))
        p["frame"] = sub(p["depth"], c32(1))
        p.if_(p.cmp(IntCompare.NE, p["depth"], c32(0), B32), lambda _p: finish_child(p["frame"], node))
        p.if_(p.cmp(IntCompare.EQ, p["depth"], c32(0), B32), lambda _p: p.__setitem__("root", node))

    def begin_member(container, slot):
        scan_string()
        p["member"] = new_node(MEMBER, p["a"], p["b"])
        st32(frame_slot(slot, PMEMBER), p["member"])
        st32(frame_slot(slot, PPHASE), c32(OBJ_COLON))

    def step():
        p["frame"] = sub(p["depth"], c32(1))
        slot = p["frame"]
        phase = ld32(frame_slot(slot, PPHASE))
        container = ld32(frame_slot(slot, PNODE))
        skip_space()
        fail_if(p.cmp(IntCompare.UGE, p["q"], p["got"], B32), EXIT_SYNTAX)
        p["byte"] = byte(p["q"])

        def key_phase(_p):
            closing = eq(p["byte"], RBRACE)
            p.if_(closing, lambda _q: (p.__setitem__("q", add(p["q"], c32(1))), close(container)))
            p.if_(ne(p["byte"], RBRACE), lambda _q: begin_member(container, slot))

        def key_strict_phase(_p):
            # after a comma a key is required: a closing brace is a trailing comma, not an empty object
            fail_if(eq(p["byte"], RBRACE), EXIT_SYNTAX)
            begin_member(container, slot)

        def colon_phase(_p):
            fail_if(ne(p["byte"], COLON), EXIT_SYNTAX)
            p["q"] = add(p["q"], c32(1))
            st32(frame_slot(slot, PPHASE), c32(OBJ_VALUE))

        def value_phase(_p):
            parse_value()
            st32(frame_slot(slot, PPHASE), c32(OBJ_NEXT))
            p.if_(ne(p["value"], 0), lambda _q: link_member(slot, container, p["value"]))

        def next_phase(_p):
            comma = eq(p["byte"], COMMA)
            closing = eq(p["byte"], RBRACE)
            p.if_(comma, lambda _q: (p.__setitem__("q", add(p["q"], c32(1))),
                                     st32(frame_slot(slot, PPHASE), c32(OBJ_KEY_STRICT))))
            p.if_(closing, lambda _q: (p.__setitem__("q", add(p["q"], c32(1))), close(container)))
            fail_if(p.all_of(ne(p["byte"], COMMA), ne(p["byte"], RBRACE)), EXIT_SYNTAX)

        def array_value_phase(_p):
            closing = eq(p["byte"], RBRACKET)
            p.if_(closing, lambda _q: (p.__setitem__("q", add(p["q"], c32(1))), close(container)))

            def take(_q):
                parse_value()
                st32(frame_slot(slot, PPHASE), c32(ARR_NEXT))
                p.if_(ne(p["value"], 0), lambda _r: link_child(slot, container, p["value"]))
            p.if_(ne(p["byte"], RBRACKET), take)

        def array_value_strict_phase(_p):
            # after a comma a value is required: a closing bracket is a trailing comma, not an empty array
            fail_if(eq(p["byte"], RBRACKET), EXIT_SYNTAX)

            def take(_q):
                parse_value()
                st32(frame_slot(slot, PPHASE), c32(ARR_NEXT))
                p.if_(ne(p["value"], 0), lambda _r: link_child(slot, container, p["value"]))
            take(_p)

        def array_next_phase(_p):
            comma = eq(p["byte"], COMMA)
            closing = eq(p["byte"], RBRACKET)
            p.if_(comma, lambda _q: (p.__setitem__("q", add(p["q"], c32(1))),
                                     st32(frame_slot(slot, PPHASE), c32(ARR_VALUE_STRICT))))
            p.if_(closing, lambda _q: (p.__setitem__("q", add(p["q"], c32(1))), close(container)))
            fail_if(p.all_of(ne(p["byte"], COMMA), ne(p["byte"], RBRACKET)), EXIT_SYNTAX)

        p.if_(eq(phase, OBJ_KEY), key_phase)
        p.if_(eq(phase, OBJ_COLON), colon_phase)
        p.if_(eq(phase, OBJ_VALUE), value_phase)
        p.if_(eq(phase, OBJ_NEXT), next_phase)
        p.if_(eq(phase, ARR_VALUE), array_value_phase)
        p.if_(eq(phase, ARR_NEXT), array_next_phase)
        p.if_(eq(phase, OBJ_KEY_STRICT), key_strict_phase)
        p.if_(eq(phase, ARR_VALUE_STRICT), array_value_strict_phase)

    def parse():
        parse_value()
        p["root"] = p["value"]
        p.while_(lambda _p: p.all_of(p.cmp(IntCompare.NE, p["depth"], c32(0), B32), eq(p["code"], 0)),
                 lambda _p: step())
        skip_space()
        fail_if(p.cmp(IntCompare.NE, p["q"], p["got"], B32), EXIT_SYNTAX)
        fail_if(eq(p["root"], 0), EXIT_SYNTAX)

    # -- canonical emission ------------------------------------------------------------------------------
    def copy_span(source, length):
        p["a"] = source
        p["b"] = add(source, length)
        p.while_(lambda _p: p.all_of(lt(p["a"], p["b"]), eq(p["code"], 0)),
                 lambda _p: (store_out(p["out"], raw_at(p["in"], p["a"])),
                             p.__setitem__("out", add(p["out"], c32(1))),
                             p.__setitem__("a", add(p["a"], c32(1)))))

    def emit_scalar(node):
        kind = get(node, KIND)
        start, end = get(node, START), get(node, END)
        p.if_(eq(kind, STRING), lambda _p: (put_out(QUOTE), copy_span(start, sub(end, start)), put_out(QUOTE)))
        p.if_(eq(kind, INTEGER), lambda _p: copy_span(start, sub(end, start)))
        for kind_value, word in ((TRUE, b"true"), (FALSE, b"false"), (NULL, b"null")):
            def take(_p, word=word, kind_value=kind_value):
                for character in word:
                    put_out(character)
            p.if_(eq(kind, kind_value), take)

    def open_frame(node):
        slot = p["emit"]
        st32(frame_slot(slot, ENODE), node)
        st32(frame_slot(slot, ECURSOR), get(node, FIRST))
        st32(frame_slot(slot, EFIRST), c32(1))
        p["emit"] = add(slot, c32(1))
        fail_if(p.cmp(IntCompare.UGE, p["emit"], c32(CAP), B32), EXIT_OVERFLOW)
        p.if_(eq(get(node, KIND), OBJECT), lambda _p: put_out(LBRACE), lambda _p: put_out(LBRACKET))

    def emit_value(node):
        kind = get(node, KIND)
        p.if_(p.any_of(eq(kind, OBJECT), eq(kind, ARRAY)),
              lambda _p: open_frame(node), lambda _p: emit_scalar(node))

    def emit_step():
        slot = sub(p["emit"], c32(1))
        p["frame"] = slot
        node = ld32(frame_slot(slot, ENODE))
        cursor = ld32(frame_slot(slot, ECURSOR))
        is_object = eq(get(node, KIND), OBJECT)

        def member_step(_p):
            p.if_(eq(cursor, 0), lambda _q: (put_out(RBRACE), p.__setitem__("emit", sub(p["emit"], c32(1)))))
            def take(_q):
                st32(frame_slot(slot, ECURSOR), get(cursor, NEXT))
                p.if_(eq(ld32(frame_slot(slot, EFIRST)), 0), lambda _r: put_out(COMMA))
                st32(frame_slot(slot, EFIRST), c32(0))
                put_out(QUOTE)
                copy_span(get(cursor, START), sub(get(cursor, END), get(cursor, START)))
                put_out(QUOTE)
                put_out(COLON)
                emit_value(get(cursor, FIRST))
            p.if_(ne(cursor, 0), take)

        def item_step(_p):
            p.if_(eq(cursor, 0), lambda _q: (put_out(RBRACKET), p.__setitem__("emit", sub(p["emit"], c32(1)))))
            def take(_q):
                st32(frame_slot(slot, ECURSOR), get(cursor, NEXT))
                p.if_(eq(ld32(frame_slot(slot, EFIRST)), 0), lambda _r: put_out(COMMA))
                st32(frame_slot(slot, EFIRST), c32(0))
                emit_value(cursor)
            p.if_(ne(cursor, 0), take)

        p.if_(is_object, member_step, item_step)

    def emit_tree():
        emit_value(p["root"])
        p.while_(lambda _p: p.all_of(p.cmp(IntCompare.NE, p["emit"], c32(0), B32), eq(p["code"], 0)),
                 lambda _p: emit_step())
        fail_if(eq(p["out"], 0), EXIT_OVERFLOW)

    # -- store buffers ----------------------------------------------------------------------------------
    def store_load8(name, offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p[f"{name}_p"], offset, p[f"{name}_m"]),
                             (B8, mem_type), attributes=(1, 1))
        p[f"{name}_m"] = memory
        return value

    def store_load64(name, offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p[f"{name}_p"], offset, p[f"{name}_m"]),
                             (B64, mem_type), attributes=(8, 1))
        p[f"{name}_m"] = memory
        return value

    def store_put8(name, offset, value):
        """Store one byte; the value must already be ``b8`` (a byte load, not a widened word)."""
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE,
                         (p[f"{name}_p"], offset, value, p[f"{name}_m"]),
                         (mem_type,), attributes=(1, 1))
        p[f"{name}_m"] = memory

    def store_put64(name, offset, value):
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE,
                         (p[f"{name}_p"], offset, p.widen(value, B64), p[f"{name}_m"]),
                         (mem_type,), attributes=(8, 1))
        p[f"{name}_m"] = memory

    # -- write ------------------------------------------------------------------------------------------
    def write_output():
        p["fd"], p["fs"] = p.op(Operation.CALL_FOREIGN, (at(PATH_TWO), c32(OPEN_WRITE), c32(CREATE_MODE),
                                                         p["fs"]), (B32, fs_type), entity=declarations["open"])
        fail_if(p.cmp(IntCompare.SLT, p["fd"], c32(0), B32), EXIT_BAD_OPEN_OUT)
        p["written"], p["fs"], p["mem"] = p.op(Operation.CALL_FOREIGN,
                                               (p["fd"], at(OUT), p["out"], p["fs"], p["mem"]),
                                               (B32, fs_type, mem_type), entity=declarations["write"])
        p["fs"] = p.op(Operation.CALL_FOREIGN, (p["fd"], p["fs"]), (B32, fs_type), entity=declarations["close"])[1]
        fail_if(p.cmp(IntCompare.NE, p["written"], p["out"], B32), EXIT_SHORT_WRITE)

    def write_store():
        path_at = PATH_TWO if store_only else PATH_THREE
        p["fd"], p["fs"] = p.op(Operation.CALL_FOREIGN, (at(path_at), c32(OPEN_WRITE), c32(CREATE_MODE),
                                                         p["fs"]), (B32, fs_type), entity=declarations["open"])
        fail_if(p.cmp(IntCompare.SLT, p["fd"], c32(0), B32), EXIT_BAD_OPEN_OUT)
        p["written"], p["fs"], p["written_m"] = p.op(
            Operation.CALL_FOREIGN, (p["fd"], p["written_p"], p["store_len"], p["fs"], p["written_m"]),
            (B32, fs_type, mem_type), entity=declarations["write"])
        p["fs"] = p.op(Operation.CALL_FOREIGN, (p["fd"], p["fs"]), (B32, fs_type), entity=declarations["close"])[1]
        fail_if(p.cmp(IntCompare.NE, p["written"], p["store_len"], B32), EXIT_SHORT_WRITE)

    EXTRA: list = []

    def environment(proc):
        """The parser's node accessors and output writer, for a resolver built on this front half.

        Calling it with another ``proc`` yields accessors bound to that function: a resolver that splits
        itself across functions builds each one from this front half's declarations and can still read the
        parsed tree, allocate, and free its view."""
        env = _accessors(proc, declarations, pointer_type, view_type, proc_type, fs_type, mem_type)
        env.update({
            "KIND": KIND, "START": START, "END": END, "FIRST": FIRST, "NEXT": NEXT,
            "OBJECT": OBJECT, "ARRAY": ARRAY, "STRING": STRING, "INTEGER": INTEGER,
            "IN": IN, "OUT": OUT, "OUT_CAP": OUT_CAP, "SCRATCH": SCRATCH, "NS": NS,
            "EXIT_SYNTAX": EXIT_SYNTAX, "EXIT_OVERFLOW": EXIT_OVERFLOW,
            "mem_type": mem_type, "view_type": view_type, "pointer_type": pointer_type,
            "proc_type": proc_type, "fs_type": fs_type,
            "declarations": declarations, "accessors": environment, "extra": EXTRA,
            "store": {name: (f"{name}_p", f"{name}_v", f"{name}_m")
                      for name, _pointer, _view, _extent, _alignment in buffers},
            "store_writer": store_writer, "store_len": "store_len", "have_three": "have_three",
            "store_load8": store_load8, "store_load64": store_load64,
            "store_put8": store_put8, "store_put64": store_put64,
        })
        return env

    def normalize():
        parse()
        if on_tree is None:
            p.if_(eq(p["code"], 0), lambda _p: emit_tree())
        else:
            p.if_(eq(p["code"], 0), lambda _p: on_tree(environment(p)))

    guard(read_input)
    guard(normalize)
    if not store_only:
        guard(write_output)
    if store_writer is not None:
        def store_output():
            fail_if(p.all_of(ne(p["store_len"], 0), eq(p["have_three"], 0)), EXIT_NO_STORE)
            p.if_(ne(p["store_len"], 0), lambda _q: write_store())
        guard(store_output)
    exit_with(p["code"])
    returns = (B32, proc_type, fs_type, mem_type) + (mem_type,) * len(buffers)
    return (p.function(returns), tuple(p.graph.objects.values()) + tuple(EXTRA))


def build_reader(name=b"xax-construct-reader", on_tree=None, view_alignment=1, extra_objects=(),
                 store_writer=None, store_only=False):
    from xax_build import (ArtifactKind, build, build_profile, build_request, package, resolve_packages,
                           snapshot_store, trust_policy)
    from xax_compiler import Kind, StoreReader, object_with_refs, verify_store, write_store

    api = win32_kernel32_api()
    stdio = win32_stdio_api(api)
    entry, objects = build_main(api, stdio, on_tree, view_alignment, store_writer, store_only)
    platform_types = (*api.types, *api.symbols, *stdio.types, *stdio.symbols)
    module = object_with_refs(Kind.MODULE, (entry,))
    app = package(name, (module,), build_entries=((b"app", entry),))
    target, profile, policy = x86_64_windows_pe_target(), build_profile(), trust_policy()
    request = build_request(app, b"app", target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
    everything = (*objects, *extra_objects, *platform_types, module, app, target, profile, policy, request)
    snapshot = snapshot_store(resolve_packages(request, everything, policy, name + b"-v1"), everything)

    available = {item.cid: item for item in snapshot.objects()}
    reachable: dict[bytes, object] = {}
    pending = [request.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(available[cid].references)
    reader = StoreReader(write_store(request.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader, snapshot, build(snapshot, request.cid)


CORPUS = (
    b"1", b"-7", b"true", b"false", b"null", b'"x"', b"[]", b"{}", b"[1,2,3]", b'{"a":1}',
    b'{"a":{"b":2}}', b"[[[]]]", b'{"a":[1,2,{"b":3}],"c":[]}', b'{"a":1,"b":2,"c":3}', b'[true,null,"",0]',
)
REFUSALS = (
    b"1.5", b"1e3", b"-", b"01", b'"a\\nb"', b'{"a":', b"1 2", b"[1", b"[1 2]", b'{"a" 1}', b'{"a":1,}', b'"\\u0041"',
    b"\xc3\xa9", b"nul", b"tru", b"[1,]", b"{,}", b'{"a":}', b'{"a":1 "b":2}', b"[,1]", b'{"":}', b"[1,,2]",
)


def check(out: Path, carriers: list[Path]) -> int:
    """Round-trip the built-in corpus, refuse everything outside the class, and match the given carriers."""
    import json

    executable, target = out / "reader.exe", out / "reader-check.out"
    good = True

    def run(payload: bytes) -> tuple[int, bytes]:
        source = out / "reader-check.in"
        source.write_bytes(payload)
        target.unlink(missing_ok=True)
        result = subprocess.run([str(executable), str(source), str(target)], capture_output=True)
        return result.returncode, target.read_bytes() if target.exists() else b""

    for payload in CORPUS:
        status, produced = run(payload)
        if status != 0 or produced != payload:
            good = False
            print(f"corpus    FAIL exit={status} in={payload!r} out={produced!r}")
    for payload in REFUSALS:
        status, produced = run(payload)
        if status != 8 or produced:
            good = False
            print(f"refusal   FAIL exit={status} in={payload!r} out={produced!r}")
    status, produced = run(b"")
    if status == 0 or produced:
        good = False
        print(f"empty     FAIL exit={status} out={produced!r}")
    print(f"corpus    {len(CORPUS)} round-trips, {len(REFUSALS)} refusals, empty {'PASS' if good else 'FAIL'}")

    for carrier in carriers:
        payload = carrier.read_bytes()
        expected = json.dumps(json.loads(payload.decode("ascii")), separators=(",", ":")).encode("ascii")
        status, produced = run(payload)
        matched = status == 0 and produced == expected
        good = good and matched
        print(f"carrier   {carrier.name:26} {len(payload):>8} bytes exit={status} "
              f"{'MATCH' if matched else 'DIFF'}")
    return 0 if good else 1


def main(argv):
    out = Path(argv[1])
    carriers = [Path(item) for item in argv[2:] if not item.startswith("--")]
    reader, snapshot, artifact = build_reader()
    out.mkdir(parents=True, exist_ok=True)
    (out / "reader.xax").write_bytes(reader.canonical_bytes())
    (out / "reader-snapshot.xax").write_bytes(snapshot.canonical_bytes())
    (out / "reader.exe").write_bytes(artifact.artifact)
    entry = next(item for item in reader.objects() if item.kind == X.Kind.FUNCTION)
    print(f"entry     {entry.cid.hex()}")
    print(f"root      {reader.root_cid.hex()}")
    print(f"store     {len(reader.canonical_bytes())} bytes")
    print(f"artifact  {len(artifact.artifact)} bytes")
    return check(out, carriers) if "--check" in argv else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
