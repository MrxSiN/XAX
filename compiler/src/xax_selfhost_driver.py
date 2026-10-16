"""Self-hosting step S10 (ADR-264, ADR-265): the compiler driver as one XAX program.

``xax_x86_64_views.compile_x86_64_views`` turns a program store into machine code: Python reads the store, the XAX
decoders check it, Python builds the backend's object table (``xax_riscv64._object_table``), and the XAX backend
lowers it.  This module makes that whole path one XAX function on the ``x86_64-linux-views-v2`` profile:

    drive(arguments: ptr<b8,READ,space 2>, heap_view<ARGUMENTS_EXTENT>, memory, filesystem, memory x BUFFERS)
        -> (the same values, bits<64> status)

``arguments`` holds three NUL-terminated paths: the program store, a target-package store (its root is the target
object), and the output file.  The driver owns every buffer (``mmap`` and ``heap.view``, released with ``munmap``),
does its own file I/O (``openat``, ``read``, ``write``, ``close``), and calls the committed XAX components directly
(S15c.4, ADR-302: a file or object past the driver's capacity is rejected with ``XAX.DRIVER.CAPACITY``):

* the store decoder (S3/S8a) and the S2 hash decide the container, its digest, and each object envelope and CID
  (S8b.1), in store order, as ``StoreReader`` and ``get`` do;
* the graph decoder (S3c/S8b.2) streams each graph fragment;
* the target package's root must be a target whose identity is a views profile (the check
  ``compile_x86_64_views`` makes, with its diagnostic);
* the XAX x86-64 backend (S7) lowers the root module's first function with the target, deciding its legality.

The output file receives the image's code (status ``IMAGE``) or the first rejection's diagnostic record as
little-endian 64-bit words (status ``REJECTED``, ``xax_selfhost_diagnostics.decode_record``).  ``DECLINED`` means
an input beyond a component's capacity or one a component defers; ``FAILED`` an I/O error.  S10e (ADR-266): before
lowering, the driver verifies the store semantically (``xax_selfhost_semantic``).

S11 (ADR-267): the store's entry is ``main``, the Linux process entry for ``x86_64-linux-views-exec-v1``: it copies
``argv[1..3]`` into an arguments view, calls ``drive``, and ends the process with ``exit_group(status)`` (``FAILED``
unless there are exactly three paths and each fits).  Under that profile the driver writes the static ELF64
executable (``xax_x86_64_views.views_executable``) instead of the bare code, so the driver lowers itself to the
executable it runs as.

S13a (ADR-281): the general driver's first argument is a command.  ``lower <store> <target package> <output>`` is the
path above.  ``build <snapshot store> <artifact> <provenance>`` is ``xax_build.build`` for the snapshot's request:
after verification it reads the snapshot, its request, and the package's build entry, makes ``build``'s rejections
(the root, external inputs, required signatures, requested artifacts) with its exact diagnostics, lowers the entry for
the request's Linux x86-64 ELF target, and writes the artifact and the canonical provenance object's envelope, the
digest and the CID derived with the S2 hash.  ``build``'s other paths (Android packages, Windows DLLs, other targets)
decline.
"""

from __future__ import annotations


from pathlib import Path

from xax_compiler import (
    CID_SIZE,
    SEMANTIC_DOMAIN,
    Kind,
    Operation,
    Permission,
    SemanticObject,
    StoreReader,
    bits_type,
    heap_view_type,
    pointer_type,
    TerminatorKind,
    x86_64_linux_exec_target,
)
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E
from xax_structured import B64, Proc
import xax_selfhost_diagnostics as D
import xax_selfhost_render as R
import xax_selfhost_render_graph as RG
import xax_selfhost_render_types as RT
import xax_selfhost_request as RQ
import xax_selfhost_resolve as RS
import xax_selfhost_writer as WR

STORE_PATH = bootstrap_dir() / "xax_compiler_driver.xax"
GENERAL_STORE_PATH = bootstrap_dir() / "xax_compiler_driver_general.xax"  # S12e.2 (ADR-276)
GENERAL_IDENTITIES = RQ.GENERAL_IDENTITIES  # S12e.2: the Linux ELF profiles
EXTENTS_EXTENT, TRAPS_EXTENT, MEMBERS_EXTENT = 1 << 25, 1 << 22, 1 << 22
IMAGE, REJECTED, DECLINED, FAILED = 0, 1, 2, 3
# The general driver's commands, argv[1] (S13a, ADR-281; S13b, ADR-282), with the file arguments each takes.
LOWER, BUILD, VERIFY, INSPECT, RESOLVE = 0, 1, 2, 3, 4  # (S13c, ADR-283: ``resolve``)
COMMANDS = {"lower": 3, "build": 3, "verify": 2, "inspect": 2, "resolve": 2}
DONE = 5  # internal status: ``verify``, ``inspect``, or ``resolve`` finished; the process exits with IMAGE
INSPECT_AT = 1 << 20  # ``inspect``'s record, in the backend output view's words (nothing is lowered)
# S15b.3c (ADR-295): a graph with an invalid use, in the workspace: the mode (1: trimmed), the first invalid use in the
# bootstrap's first pass (its code, use block and node, value tag/block/index/result, the use block's order position,
# the dominator bitset width), the use block's dominators, the native block order, and each block's position in it.
INV_AT = 36 << 20
I_MODE, I_CODE, I_UB, I_UN, I_TAG, I_VB, I_VI, I_VR, I_POS, I_W, I_NODE = range(11)  # I_NODE: the first use is a node's
I_DOMS, I_ORDER = INV_AT + 64, INV_AT + 2048
I_POSITION = I_ORDER + (1 << 16)
ARGUMENTS_EXTENT = 4096
INPUTS_EXTENT = 4096  # S15c.2: ``INPUTS_LIMIT`` digests and one staged
CHUNK = 1 << 16
from xax_x86_64_views import EXEC_IDENTITY, IDENTITIES as VIEWS_IDENTITIES  # noqa: E402
AT_FDCWD = 0xFFFFFF9C
O_OUTPUT = 0x241  # O_WRONLY | O_CREAT | O_TRUNC
MODE_OUTPUT = 0o644


def _components():
    """The committed components and their interface types."""
    import xax_selfhost_blake3 as H
    import xax_selfhost_graph as G
    import xax_selfhost_store as S
    import xax_selfhost_x86_64_backend as X
    from xax_selfhost_facts import VIEW_TYPES

    return H, G, S, X, VIEW_TYPES


class _Driver(E):
    """Arithmetic and control from the facts engine's helper; ``op``/``ov``/``om`` are the backend's output view, so
    ``E.ld``/``E.st`` and the ``xax_selfhost_diagnostics`` writers address it."""

    def __init__(self, proc: Proc, views: dict[str, tuple[str, str, str, int]]):
        super().__init__(proc, None)
        self.views = views  # name -> (pointer, token, memory, element bytes)
        self._names = 0

    def let(self, stem: str, value=0) -> str:
        self._names += 1
        name = f"{stem}_{self._names}"
        self.var(name, value)
        return name

    def __getitem__(self, name: str):
        return self.p[name]

    def _at(self, offset):
        return self.p.op1(Operation.INT_TRUNCATE, (self.v(offset),), bits_type(32))

    def load(self, view: str, offset, size: int = 1):
        """``size`` bytes at byte ``offset`` of ``view`` (a byte view reads 1, 4, or 8; a word view its word)."""
        pointer, _token, memory, _element = self.views[view]
        p = self.p
        value, p[memory] = p.op(Operation.CHECKED_LOAD_BITS_LE, (p[pointer], self._at(offset), p[memory]), (bits_type(8 * size), D_MEM),
                                attributes=(size, 1))
        return value if size == 8 else p.op1(Operation.INT_ZERO_EXTEND, (value,), B64)

    def store(self, view: str, offset, value, size: int = 1):
        pointer, _token, memory, _element = self.views[view]
        p = self.p
        value = self.v(value)
        if size != 8:
            value = p.op1(Operation.INT_TRUNCATE, (value,), bits_type(8 * size))
        p[memory] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p[pointer], self._at(offset), value, p[memory]), D_MEM, attributes=(size, 1))

    def triple(self, view: str, pointer=None):
        names = self.views[view]
        return (self.p[names[0]] if pointer is None else pointer, self.p[names[1]], self.p[names[2]])

    def take(self, view: str, values):
        """A callee gave back ``view``'s token and memory (its pointer is the one this driver holds)."""
        _pointer, token, memory, _element = self.views[view]
        self.p[token], self.p[memory] = values[1], values[2]

    def narrowed(self, view: str, pointer_type_):
        """``pointer.cast`` of ``view``'s pointer to the read-only pointer a component takes."""
        return self.p.op1(Operation.POINTER_CAST, (self.p[self.views[view][0]],), pointer_type_)

    def syscall(self, declaration, operands, results):
        return self.p.op(Operation.CALL_FOREIGN, tuple(self.v(item) for item in operands), results, entity=declaration)

    def copy(self, source: str, source_at, target: str, target_at, count):
        """Copy ``count`` bytes between byte views (eight at a time, then one)."""
        src, dst, left = self.let("from", source_at), self.let("to", target_at), self.let("left", count)

        def chunk(size: int):
            def step():
                self.store(target, self[dst], self.load(source, self[src], size), size)
                self.set(src, self.add(self[src], size))
                self.set(dst, self.add(self[dst], size))
                self.set(left, self.sub(self[left], size))
            return step

        self.while_(lambda: self.le(8, self[left]), chunk(8))
        self.while_(lambda: self.ne(self[left], 0), chunk(1))

    def uleb_size(self, value):
        size, rest = self.let("size", 1), self.let("rest", value)
        self.while_(lambda: self.le(128, self[rest]), lambda: (self.set(rest, self.udiv(self[rest], 128)), self.set(size, self.add(self[size], 1))))
        return self[size]

    def cid_word(self, view: str, at, word: int):
        """Bytes ``8 word .. 8 word + 8`` of the CID at ``at`` as one big-endian word (``xax_riscv64._cid_words``)."""
        value = self.c(0)
        for k in range(8):
            value = self.add(self.mul(value, 256), self.load(view, self.add(at, 8 * word + k)))
        return value

    def same_constant(self, view: str, at, data: bytes):
        """1 when ``view`` holds ``data`` at ``at``."""
        same = self.let("same", 1)
        for k, byte in enumerate(data):
            self.set(same, self.and_(self[same], self.flag(self.eq(self.load(view, self.add(at, k)), byte))))
        return self[same]

    def same_bytes(self, x_view: str, x_at, y_view: str, y_at, count: int):
        same = self.let("same", 1)
        for k in range(count):
            self.set(same, self.and_(self[same], self.flag(self.eq(self.load(x_view, self.add(x_at, k)), self.load(y_view, self.add(y_at, k))))))
        return self[same]


D_MEM = None  # the memory effect type, bound by ``build_driver_program``


def build_driver_program(general: bool = False) -> tuple[StoreReader, SemanticObject]:
    """The driver's store and entry; with ``general`` (S12e.2, ADR-276), the general driver: the same driver, which also
    lowers the Linux ELF profiles with the general x86-64 backend program."""
    global D_MEM
    from xax_linux import linux_api

    H, G, S, X, VIEW_TYPES = _components()
    import xax_selfhost_cfg as CF
    import xax_selfhost_facts as FA
    import xax_selfhost_semantic as SM
    import xax_selfhost_typing as TY
    import xax_selfhost_verify as VF
    api = linux_api()
    B32 = api.b32
    MEM = D_MEM = api.memory_effect
    FS = api.filesystem_effect
    bytes_rw = api.bytes_rw
    in_pointer, in_view, _m, out_pointer, out_view, _m2 = VIEW_TYPES
    backend_in_rw = pointer_type(bits_type(64), Permission.READ_WRITE, 8, space=2)
    # name -> (pointer type the driver holds, extent, alignment)
    buffers = {
        "data": (bytes_rw, S.DATA_EXTENT, 1),             # the store file; decoded through a read-only cast
        "object": (bytes_rw, S.DATA_EXTENT, 1),           # one envelope, its digest, and its CID preimage
        "decoded": (S.OUT_POINTER, S.OUT_EXTENT, 4),      # the container decoder's output
        "envelope": (S.OUT_POINTER, S.OUT_EXTENT, 4),     # the object decoder's output
        "scratch": (H.SCRATCH_POINTER, H.SCRATCH_EXTENT, 4),
        "body": (bytes_rw, G.BODY_EXTENT, 1),
        "stream": (G.OUT_POINTER, G.OUT_EXTENT, 8),
        "table": (backend_in_rw, in_view_extent(in_view), 8),
        "image": (out_pointer, out_view_extent(out_view), 8),
        "chunk": (bytes_rw, CHUNK, 1),
        "path": (bytes_rw, ARGUMENTS_EXTENT, 1),
        # S10e (ADR-266): the store verifier's object table, the semantic marshals' workspace, the CFG program's views.
        "vtable": (backend_in_rw, in_view_extent(in_view), 8),
        "work": (out_pointer, out_view_extent(out_view), 8),
        "cfgin": (backend_in_rw, CF.IN_EXTENT, 8),
        "cfgout": (CF.OUT_POINTER, CF.OUT_EXTENT, 8),
        # S11 (ADR-267): the three paths, copied from argv, and one argument as ``arg_copy`` gives it.
        "arguments": (bytes_rw, ARGUMENTS_EXTENT, 1),
        "argument": (bytes_rw, ARGUMENTS_EXTENT, 1),
    }
    if general:
        # S12e.2: per graph, the verifier's pointer extents and its trap payload heads (``general_object_table``).
        buffers["extents"] = (backend_in_rw, EXTENTS_EXTENT, 8)
        buffers["traps"] = (backend_in_rw, TRAPS_EXTENT, 8)
        buffers["members"] = (backend_in_rw, MEMBERS_EXTENT, 8)  # the group member functions the store does not hold
        buffers["batch"] = (bytes_rw, WR.IN_EXTENT, 1)  # S13c: the S9 writer's batch
        buffers["written"] = (bytes_rw, WR.BUF_EXTENT, 1)  # S14b (ADR-285): the S9 writer's buffer; the store it writes
        buffers["inputs"] = (bytes_rw, INPUTS_EXTENT, 1)  # S15c.2 (ADR-300): the input files' digests, sorted, each once
    names = {"data": "dp", "object": "xp", "decoded": "up", "envelope": "ep", "scratch": "sp", "body": "gp", "stream": "hp",
             "table": "ip", "image": "op", "chunk": "cp", "path": "pp", "vtable": "tp", "work": "wp", "cfgin": "kp", "cfgout": "qp",
             "arguments": "ap", "argument": "zp", "extents": "np", "traps": "jp", "members": "mp", "batch": "bp", "written": "lp", "inputs": "fp"}
    views = {}
    for name in buffers:
        pointer_name = names[name]
        stem = pointer_name[0]
        views[name] = (pointer_name, f"{stem}v", f"{stem}m", 1 if buffers[name][0] == bytes_rw else 8)
    PROCESS = api.process_effect
    parameters = [("fs", FS), ("process", PROCESS)] + [(f"mem_{name}", MEM) for name in buffers]
    proc = Proc(parameters)
    w = _Driver(proc, views)

    # Owned memory: one mapping and one view per buffer, each on its own memory effect.
    for name, (pointer_type_, extent, alignment) in buffers.items():
        pointer_name, token_name, memory_name, _element = views[name]
        raw, owner, memory = w.syscall(api.mmap_anonymous, (w.p.const(extent, B64), proc[f"mem_{name}"]), (bytes_rw, api.heap_owner, MEM))
        pointer, token, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, memory), (pointer_type_, heap_view_type(extent), MEM),
                                         attributes=(extent, 4096))
        proc.drop(f"mem_{name}")
        proc.let(pointer_name, pointer_type_, pointer)
        proc.let(token_name, heap_view_type(extent), token)
        proc.let(memory_name, MEM, memory)

    status = w.let("status", IMAGE)

    def running():
        return w.eq(w[status], IMAGE)

    def when(body):
        w.if_(running(), body)

    def stop(code):
        w.set(status, code)

    # -- S11: argv[1..3], each NUL-terminated, into ``arguments`` ------------------------------------------------
    from xax_linux import linux_startup_api

    startup = linux_startup_api(api)
    argc = proc.op1(Operation.CALL_FOREIGN, (), B64, entity=startup.argc)
    if general:
        arguments = w.let("arguments_count", argc)
    else:
        w.if_(w.ne(argc, 4), lambda: stop(FAILED))
    argument_end = w.let("argument_end", 0)
    if general:
        # S13a (ADR-281), S13b (ADR-282): argv[1] is the command (``COMMANDS``), followed by its file arguments; an
        # unknown command or another count FAILED.
        mode = w.let("mode", LOWER)
        files_count = w.let("files", 0)

        def command():
            count, proc["zm"] = proc.op(Operation.CALL_FOREIGN, (proc.const(1, B64), proc["zp"], proc["zm"]), (B64, MEM), entity=startup.arg_copy)
            n = w.let("n", count)
            known, chosen, files = w.c(0), w.c(0), w.c(0)
            for value, (word, paths) in enumerate(COMMANDS.items()):
                matched = w.flag(w.both(w.eq(w[n], len(word)), w.ne(w.same_constant("argument", 0, word.encode()), 0)))
                known, chosen, files = w.or_(known, matched), w.add(chosen, w.mul(matched, value)), w.add(files, w.mul(matched, paths))
            w.set(mode, chosen)
            w.set(files_count, files)
            # S15c.2 (ADR-300): ``build`` and ``resolve`` take up to ``INPUTS_LIMIT`` external input files after their own.
            takes_inputs = w.either(w.eq(w[mode], BUILD), w.eq(w[mode], RESOLVE))
            extra = w.sub(w[arguments], w.add(files, 2))
            w.if_(w.either(w.eq(known, 0), w.lt(w[arguments], w.add(files, 2)),
                           w.both(w.ne(extra, 0), w.either(w.not_(takes_inputs), w.lt(RQ.INPUTS_LIMIT, extra)))), lambda: stop(FAILED))

        w.if_(w.lt(w[arguments], 4), lambda: stop(FAILED), lambda: when(command))

    def argument(index):
        count, proc["zm"] = proc.op(Operation.CALL_FOREIGN, (w.v(index), proc["zp"], proc["zm"]), (B64, MEM), entity=startup.arg_copy)
        n = w.let("n", count)
        at = argument_end
        fits = w.both(w.lt(w[n], ARGUMENTS_EXTENT), w.lt(w.add(w[at], w[n]), ARGUMENTS_EXTENT))  # and its NUL
        w.if_(fits, lambda: (w.copy("argument", 0, "arguments", w[at], w[n]), w.store("arguments", w.add(w[at], w[n]), 0),
                             w.set(at, w.add(w.add(w[at], w[n]), 1))), lambda: stop(FAILED))

    if general:
        copied = w.let("copied", 2)
        w.while_(lambda: w.both(w.lt(w[copied], w[arguments]), running()), lambda: (argument(w[copied]), w.set(copied, w.add(w[copied], 1))))
    else:
        for index in (1, 2, 3):
            when(lambda index=index: argument(index))

    # -- paths ---------------------------------------------------------------------------------------------------
    def path(index: int):
        """Copy argument ``index`` (NUL-terminated) to the path buffer; FAILED when it does not end in the view."""
        at, k = w.let("argument", 0), w.let("skip", 0)

        def skip():
            w.while_(lambda: w.both(w.lt(w[at], ARGUMENTS_EXTENT), w.ne(w.load("arguments", w[at]), 0)), lambda: w.set(at, w.add(w[at], 1)))
            w.set(at, w.add(w[at], 1))
            w.set(k, w.add(w[k], 1))

        w.while_(lambda: w.both(w.lt(w[k], index), w.lt(w[at], ARGUMENTS_EXTENT)), skip)
        n = w.let("n", 0)
        w.while_(lambda: w.both(w.lt(w.add(w[at], w[n]), ARGUMENTS_EXTENT), w.ne(w.load("arguments", w.add(w[at], w[n])), 0)),
                 lambda: w.set(n, w.add(w[n], 1)))
        w.if_(w.lt(w.add(w[at], w[n]), ARGUMENTS_EXTENT), lambda: (w.copy("arguments", w[at], "path", 0, w[n]), w.store("path", w[n], 0)),
              lambda: stop(FAILED))

    def open_path(index: int, flags: int, mode: int, guard=None) -> str:
        """``openat`` of argument ``index`` while ``guard()`` holds (default: still running); the descriptor's name."""
        path(index)
        fd = w.let("fd", 0)

        def opened():
            pointer, token, memory = w.triple("path")
            narrowed = w.narrowed("path", api.bytes_read)
            result, w.p["fs"], w.p[views["path"][2]] = w.syscall(api.openat, (w.p.const(AT_FDCWD, B32), narrowed, w.p.const(flags, B32),
                                                                             w.p.const(mode, B32), w.p["fs"], memory), (B64, FS, MEM))
            w.set(fd, result)
            w.if_(w.le(1 << 63, w[fd]), lambda: stop(FAILED))

        w.if_(running() if guard is None else guard(), opened)
        return fd

    def fd32(fd: str):
        return w.p.op1(Operation.INT_TRUNCATE, (w[fd],), B32)

    def close(fd: str):
        _result, w.p["fs"] = w.syscall(api.close, (fd32(fd), w.p["fs"]), (B64, FS))

    # -- reading a store into ``data`` ---------------------------------------------------------------------------
    read_rw = api.read
    length = w.let("length", 0)
    limit = S.DATA_EXTENT - 2 * CID_SIZE - 64  # the digest after the data, and the hash's block reads past its end

    def capacity(entity: str, rule: str, limit_bytes: int):
        """S15c.4 (ADR-302): an input past the driver's declared capacity is rejected, with the driver's own record."""
        D.begin(w)
        D.text(w, "XAX.DRIVER.CAPACITY")
        D.text(w, entity)
        D.text(w, rule)
        D.integer(w, limit_bytes)
        D.text(w, "larger")
        stop(REJECTED)

    def read_store(index, entity: str = "store"):
        fd = open_path(index, 0, 0)

        def read_all():
            w.set(length, 0)
            going = w.let("going", 1)

            def step():
                count = w.let("count", 0)
                result, w.p["fs"], w.p[views["chunk"][2]] = w.syscall(read_rw, (fd32(fd), w.p[views["chunk"][0]], w.p.const(CHUNK, B64), w.p["fs"],
                                                                                w.p[views["chunk"][2]]), (B64, FS, MEM))
                w.set(count, result)
                w.if_(w.le(1 << 63, w[count]), lambda: (stop(FAILED), w.set(going, 0)), lambda: w.if_(
                    w.eq(w[count], 0), lambda: w.set(going, 0), lambda: w.if_(
                        w.lt(limit, w.add(w[length], w[count])), lambda: (capacity(entity, "DRIVER-FILE-CAPACITY", limit), w.set(going, 0)), lambda: (
                            w.copy("chunk", 0, "data", w[length], w[count]), w.set(length, w.add(w[length], w[count]))))))

            w.while_(lambda: w.ne(w[going], 0), step)
            close(fd)

        when(read_all)

    # -- the components ------------------------------------------------------------------------------------------
    decoder_reader, decoder = S.load_decoder_program()
    graph_reader, graph_decoder = G.load_graph_decoder_program()
    backend_reader, backend = X.load_backend_program()
    if general:
        import xax_selfhost_general_image as GI
        import xax_selfhost_x86_64_general as GEN

        general_reader, general_program = GEN.load_general_program()
        writer_reader, writer = WR.load_writer_program()  # S13c
    hash_at, hash_objects = H.hash_function(bytes_rw, heap_view_type(S.DATA_EXTENT), based=True)
    decoder_triples = (S.DATA_POINTER, S.DATA_VIEW, MEM, S.OUT_POINTER, S.OUT_VIEW, MEM)

    def decode(source: str, output: str, count, mode: int):
        """The store decoder over ``source`` (``count`` bytes) into ``output``; its status word."""
        results = proc.op(Operation.CALL_DIRECT, (*w.triple(source, w.narrowed(source, S.DATA_POINTER)), *w.triple(output), w.v(count),
                                                  w.p.const(mode, B64)), decoder_triples, entity=decoder)
        w.take(source, results[:3])
        w.take(output, results[3:])
        return w.load(output, 0, 4)

    def hash_span(source: str, base, count):
        """The S2 hash of ``source[base : base + count]``; the digest is at ``scratch[DIGEST_OFFSET]``."""
        results = proc.op(Operation.CALL_DIRECT, (*w.triple(source), *w.triple("scratch"), w.v(base), w.v(count)),
                          (bytes_rw, heap_view_type(S.DATA_EXTENT), MEM, H.SCRATCH_POINTER, H.SCRATCH_VIEW, MEM), entity=hash_at)
        w.take(source, results[:3])
        w.take("scratch", results[3:])

    def digest_to(target: str, at):
        for word in range(CID_SIZE // 4):
            w.store(target, w.add(at, 4 * word), w.load("scratch", H.DIGEST_OFFSET + 4 * word, 4), 4)

    def record_from_decoder(output: str):
        """The decoder's rejection record (32-bit word pairs) as the driver's record (64-bit words at ``D.DIAG_AT``)."""
        end = w.let("end", w.load(output, 4 * S.DIAG_AT, 4))
        k, n = w.let("pair", S.DIAG_AT + 1), w.let("put", D.DIAG_AT + 1)

        def step():
            low, high = w.load(output, w.mul(w[k], 4), 4), w.load(output, w.mul(w.add(w[k], 1), 4), 4)
            w.st(w[n], w.add(low, w.mul(high, 1 << 32)))
            w.set(k, w.add(w[k], 2))
            w.set(n, w.add(w[n], 1))

        w.while_(lambda: w.lt(w[k], w[end]), step)
        w.st(D.DIAG_AT, w[n])
        stop(REJECTED)

    def outcome(code, output: str, declined_codes=(2,)):
        """Map a decoder status word: REJECT (1) copies its record; any other status but ACCEPT declines."""
        w.if_(w.eq(code, 1), lambda: record_from_decoder(output), lambda: w.if_(w.ne(code, 0), lambda: stop(DECLINED)))

    def decode_container():
        """``StoreReader``: the container with its digest (S8a), or the rejection."""
        first = w.let("first", decode("data", "decoded", w[length], S.MODE_HASH))

        def digest():
            hash_span("data", 0, w.load("decoded", 4, 4))
            digest_to("data", w[length])
            w.set(first, decode("data", "decoded", w[length], S.MODE_VERIFY))

        w.if_(w.eq(w[first], S.NEED_DIGEST), digest)
        outcome(w[first], "decoded")

    def record_word(position, field: int):
        return w.load("decoded", w.mul(w.add(S.HEADER_WORDS, w.add(w.mul(position, S.RECORD_WORDS), field)), 4), 4)

    def check_object(position):
        """``StoreReader.get`` (S8b.1): record ``position``'s envelope, its CID re-derived; the rejection on failure."""
        record_at, record_length = record_word(position, 0), record_word(position, 1)
        envelope = w.let("envelope", w.add(w.uleb_size(record_length), record_length))
        offset = w.let("offset", record_at)
        w.if_(w.eq(record_word(position, 3), 0), lambda: stop(DECLINED))  # an envelope the container pass left to the bootstrap
        w.if_(w.lt(S.DATA_EXTENT - 4 * CID_SIZE, w.mul(w[envelope], 2)),  # the envelope and its preimage (S15c.4)
              lambda: capacity("object", "DRIVER-OBJECT-CAPACITY", (S.DATA_EXTENT - 4 * CID_SIZE) // 2))

        def checked():
            w.copy("data", w[offset], "object", 0, w[envelope])
            code = w.let("code", decode("object", "envelope", w[envelope], S.MODE_OBJECT_HASH))

            def digest():
                start, end = w.let("start", w.load("envelope", 4, 4)), w.let("stop", w.load("envelope", 8, 4))
                stage = w.let("stage", w.add(w[envelope], 2 * CID_SIZE))
                for k, byte in enumerate(SEMANTIC_DOMAIN):
                    w.store("object", w.add(w[stage], k), byte)
                w.copy("object", w[start], "object", w.add(w[stage], len(SEMANTIC_DOMAIN)), w.sub(w[end], w[start]))
                hash_span("object", w[stage], w.add(len(SEMANTIC_DOMAIN), w.sub(w[end], w[start])))
                digest_to("object", w[envelope])
                w.set(code, decode("object", "envelope", w[envelope], S.MODE_OBJECT_VERIFY))

            w.if_(w.eq(w[code], S.NEED_DIGEST), digest)
            outcome(w[code], "envelope")

        when(checked)

    # -- S15c.2 (ADR-300): the external input files, hashed (BLAKE3, as ``verify_external_bytes``), sorted, each once -----
    inputs_count = w.let("inputs_count", 0)
    if general:
        def input_files():
            given = w.let("given", w.sub(w[arguments], w.add(w[files_count], 2)))
            i = w.let("input", 0)

            def each():
                read_store(w.add(w[files_count], w[i]), "external-input")

                def place():
                    hash_span("data", 0, w[length])
                    staged = RQ.INPUTS_LIMIT * CID_SIZE
                    digest_to("inputs", staged)
                    before, duplicate = w.let("before", 0), w.let("duplicate", 0)

                    def compare():
                        at = w.mul(w[j], CID_SIZE)
                        less, equal = w.let("less", 0), w.let("equal", 1)
                        for word in range(4):
                            x, y = w.let("x", w.cid_word("inputs", at, word)), w.let("y", w.cid_word("inputs", staged, word))
                            w.if_(w.ne(w[equal], 0), lambda: w.if_(w.lt(w[x], w[y]), lambda: (w.set(less, 1), w.set(equal, 0)),
                                                                   lambda: w.if_(w.lt(w[y], w[x]), lambda: w.set(equal, 0))))
                        w.set(before, w.add(w[before], w[less]))
                        w.set(duplicate, w.or_(w[duplicate], w[equal]))
                        w.set(j, w.add(w[j], 1))

                    j = w.let("j", 0)
                    w.while_(lambda: w.lt(w[j], w[inputs_count]), compare)

                    def insert():
                        tail = w.let("tail", w[inputs_count])
                        w.while_(lambda: w.lt(w[before], w[tail]), lambda: (
                            w.copy("inputs", w.mul(w.sub(w[tail], 1), CID_SIZE), "inputs", w.mul(w[tail], CID_SIZE), CID_SIZE),
                            w.set(tail, w.sub(w[tail], 1))))
                        w.copy("inputs", staged, "inputs", w.mul(w[before], CID_SIZE), CID_SIZE)
                        w.set(inputs_count, w.add(w[inputs_count], 1))

                    w.if_(w.eq(w[duplicate], 0), insert)

                when(place)
                w.set(i, w.add(w[i], 1))

            w.while_(lambda: w.both(w.lt(w[i], w[given]), running()), each)

        when(input_files)

    # -- the program store ---------------------------------------------------------------------------------------
    read_store(0)
    when(decode_container)
    objects = w.let("objects", 0)
    when(lambda: w.set(objects, w.load("decoded", 8, 4)))
    k = w.let("checked", 0)
    w.while_(lambda: w.both(w.lt(w[k], w[objects]), running()), lambda: (check_object(w[k]), w.set(k, w.add(w[k], 1))))

    def find(cid_at):
        """The record whose CID is the one at ``data[cid_at]`` (NONE-like: ``objects`` when absent)."""
        found, j = w.let("found", w[objects]), w.let("search", 0)

        def step():
            same = w.same_bytes("data", cid_at, "data", record_word(w[j], 2), CID_SIZE)
            w.if_(w.ne(same, 0), lambda: w.set(found, w[j]))
            w.set(j, w.add(w[j], 1))

        w.while_(lambda: w.both(w.lt(w[j], w[objects]), w.eq(w[found], w[objects])), step)
        return found

    # The entry: the first module in store order, then its first function reference (``load_*_program``,
    # ``host_image``).
    entry = w.let("entry", 0)

    def choose_entry():
        module_record, j = w.let("module", w[objects]), w.let("scan", 0)

        def scan():
            w.if_(w.eq(record_word(w[j], 4), int(Kind.MODULE)), lambda: w.set(module_record, w[j]))
            w.set(j, w.add(w[j], 1))

        w.while_(lambda: w.both(w.lt(w[j], w[objects]), w.eq(w[module_record], w[objects])), scan)

        def function():
            w.set(entry, w[objects])
            r = w.let("reference", 0)

            def step():
                candidate = find(w.add(record_word(w[module_record], 6), w.mul(w[r], CID_SIZE)))
                w.if_(w.both(w.lt(w[candidate], w[objects]), w.eq(record_word(w[candidate], 4), int(Kind.FUNCTION))),
                      lambda: w.set(entry, w[candidate]))
                w.set(r, w.add(w[r], 1))

            w.while_(lambda: w.both(w.lt(w[r], record_word(w[module_record], 5)), w.eq(w[entry], w[objects])), step)
            w.if_(w.eq(w[entry], w[objects]), lambda: stop(DECLINED))

        w.if_(w.lt(w[module_record], w[objects]), function, lambda: stop(DECLINED))

    if general:
        when(lambda: w.if_(w.eq(w[mode], LOWER), choose_entry))  # S13a: ``build`` takes the package's build entry
    else:
        when(choose_entry)

    # -- S10e (ADR-266): semantic verification, every decision by an XAX component -------------------------------
    semantic, semantic_objects = SM.build_functions()
    typing_reader, typing_program = TY.load_typing_program()
    verifier_reader, verifier_program = VF.load_verifier_program()
    cfg_reader, cfg_program = CF.load_cfg_program()
    t_limit = in_view_extent(in_view) // 8
    t_words = w.let("t_words", 2)

    def t_put(value):
        w.if_(w.lt(w[t_words], t_limit), lambda: w.store("vtable", w.mul(w[t_words], 8), value, 8), lambda: stop(DECLINED))
        w.set(t_words, w.add(w[t_words], 1))

    def work_word(index):
        return w.load("work", w.mul(index, 8), 8)

    def set_work(index, value):
        w.store("work", w.mul(index, 8), value, 8)

    def verify_reject(position, rule: str, actual):
        D.begin(w)
        D.text(w, "XAX.DRIVER.VERIFY")
        D.cid(w, [w.cid_word("data", record_word(position, 2), word) for word in range(4)])
        D.text(w, rule)
        D.text(w, "proven by the XAX verifier components")
        D.integer(w, actual)
        stop(REJECTED)

    def graph_stream(position, on_rejected):
        """The graph decoder's stream of record ``position`` in ``stream`` (status word 0); ``on_rejected()`` copies
        its rejection record; a defer declines."""
        body_at, body_length = record_word(position, 7), record_word(position, 8)
        e_at, e_length = w.let("g_at", body_at), w.let("g_length", body_length)
        w.if_(w.lt(G.BODY_EXTENT - CID_SIZE, w[e_length]), lambda: stop(DECLINED))

        def decode_graph():
            w.copy("data", w[e_at], "body", 0, w[e_length])
            w.copy("data", record_word(position, 2), "body", w[e_length], CID_SIZE)
            results = proc.op(Operation.CALL_DIRECT, (*w.triple("body", w.narrowed("body", G.BODY_POINTER)), *w.triple("stream"), w[e_length],
                                                      record_word(position, 5)), (G.BODY_POINTER, G.BODY_VIEW, MEM, G.OUT_POINTER, G.OUT_VIEW, MEM),
                              entity=graph_decoder)
            w.take("body", results[:3])
            w.take("stream", results[3:])
            code = w.let("gs_status", w.load("stream", 0, 8))
            w.if_(w.eq(w[code], 1), on_rejected, lambda: w.if_(w.ne(w[code], 0), lambda: stop(DECLINED)))

        when(decode_graph)

    def graph_rejected():
        end = w.let("graph_end", w.load("stream", 8 * G.DIAG_AT, 8))
        q, n = w.let("gq", G.DIAG_AT + 1), w.let("gn", D.DIAG_AT + 1)
        w.while_(lambda: w.lt(w[q], w[end]), lambda: (w.st(w[n], w.load("stream", w.mul(w[q], 8), 8)), w.set(q, w.add(w[q], 1)), w.set(n, w.add(w[n], 1))))
        w.st(D.DIAG_AT, w[n])
        stop(REJECTED)

    def object_table():
        """``xax_selfhost_verify.object_table(store objects, [root])``."""
        w.store("vtable", 0, w[objects], 8)
        root = find(w.load("decoded", 4 * 7, 4))
        w.store("vtable", 8, w[root], 8)
        w.if_(w.eq(w[root], w[objects]), lambda: stop(DECLINED))
        position = w.let("t_object", 0)

        def each():
            kind, references = w.let("t_kind", record_word(w[position], 4)), w.let("t_refs", record_word(w[position], 5))
            t_put(w[kind])
            t_put(w[references])
            r = w.let("t_ref", 0)

            def reference():
                found = find(w.add(record_word(w[position], 6), w.mul(w[r], CID_SIZE)))
                t_put(w.sel(w.eq(w[found], w[objects]), FA.NONE, w[found]))
                w.set(r, w.add(w[r], 1))

            w.while_(lambda: w.lt(w[r], w[references]), reference)
            put_words = [w.cid_word("data", record_word(w[position], 2), word) for word in range(4)]
            for word in put_words:
                t_put(word)
            body_at, body_length = w.let("t_body_at", record_word(w[position], 7)), w.let("t_body_length", record_word(w[position], 8))

            def graph():
                graph_stream(w[position], lambda: None)  # S15b.1: a rejection waits for its turn in ``verify_store``'s order

                def stream():
                    count = w.let("t_stream", w.sub(w.load("stream", 8, 8), 2))
                    t_put(w[count])
                    q = w.let("q", 0)
                    w.while_(lambda: w.both(w.lt(w[q], w[count]), running()), lambda: (t_put(w.load("stream", w.mul(w.add(w[q], 2), 8), 8)), w.set(q, w.add(w[q], 1))))
                    t_put(w[body_length])
                    q2 = w.let("q", 0)
                    w.while_(lambda: w.both(w.lt(w[q2], w[body_length]), running()), lambda: (t_put(w.load("data", w.add(w[body_at], w[q2]))), w.set(q2, w.add(w[q2], 1))))
                    t_put(w.flag(w.eq(w.load("stream", 0, 8), 1)))  # 1: the graph decoder rejected it (a prefix)

                when(stream)

            def plain():
                t_put(w[body_length])
                q = w.let("q", 0)
                w.while_(lambda: w.both(w.lt(w[q], w[body_length]), running()), lambda: (t_put(w.load("data", w.add(w[body_at], w[q]))), w.set(q, w.add(w[q], 1))))

            w.if_(w.eq(w[kind], int(Kind.GRAPH_FRAGMENT)), graph, plain)
            w.set(position, w.add(w[position], 1))

        w.while_(lambda: w.both(w.lt(w[position], w[objects]), running()), each)

    def helper(name: str):
        results = proc.op(Operation.CALL_DIRECT, (*w.triple("vtable", w.narrowed("vtable", in_pointer)), *w.triple("work")), (B64, *VIEW_TYPES),
                          entity=semantic[name])
        w.take("vtable", results[1:4])
        w.take("work", results[4:])
        w.if_(w.ne(work_word(SM.CTRL + SM.C_STATUS), SM.OK), lambda: stop(DECLINED))

    type_renderers, type_objects = RT.build_functions()  # S15b.2 (ADR-289)
    requests, request_objects = RQ.build_functions() if general else ({}, ())
    resolvers, resolve_objects = RS.build_functions() if general else ({}, ())

    def request_helper(name: str, functions=requests):
        """S13a: an ``xax_selfhost_request`` (S13c: ``xax_selfhost_resolve``; S15b.2: ``xax_selfhost_render_types``)
        function over the object table and the workspace."""
        results = proc.op(Operation.CALL_DIRECT, (*w.triple("vtable", w.narrowed("vtable", in_pointer)), *w.triple("work")),
                          (B64, *VIEW_TYPES), entity=functions[name])
        w.take("vtable", results[1:4])
        w.take("work", results[4:])

    def typing():
        """The typing program over the workspace's marshal, copied to ``table``; its output in ``image``."""
        count = w.let("m_count", work_word(SM.CTRL + SM.C_LENGTH))
        w.if_(w.lt(t_limit, w[count]), lambda: stop(DECLINED))
        q = w.let("q", 0)
        w.while_(lambda: w.both(w.lt(w[q], w[count]), running()), lambda: (w.store("table", w.mul(w[q], 8), work_word(w.add(SM.MARSHAL_AT, w[q])), 8),
                                                                           w.set(q, w.add(w[q], 1))))

        def run():
            w.st(RG.OUTCOME_AT + RG.O_MODE, work_word(INV_AT + I_MODE))  # S15b.3c: a trimmed graph's first pass runs whole
            results = proc.op(Operation.CALL_DIRECT, (*w.triple("table", w.narrowed("table", in_pointer)), *w.triple("image")), VIEW_TYPES,
                              entity=typing_program)
            w.take("table", results[:3])
            w.take("image", results[3:])
            w.if_(w.ne(w.ld(0), TY.ACCEPT), lambda: stop(DECLINED))

        when(run)

    def object_verdicts():
        """``_xax_prove_objects``: every type and constant proven; the verdict flags follow the object table."""
        helper("index_objects")
        when(lambda: helper("objects_marshal"))
        when(typing)
        entries = w.let("entries", work_word(SM.MARSHAL_AT))
        o = w.let("flag_object", 0)

        def flag():
            listed = w.let("listed", work_word(w.add(SM.LISTED, w[o])))
            proven = w.let("proven", 0)
            w.if_(w.ne(w[listed], FA.NONE), lambda: w.set(proven, w.flag(w.eq(w.ld(w.add(w.add(TY.TABLE, w.mul(w[entries], TY.OBJOK)), w[listed])), 1))))
            t_put(w[proven])
            kind = record_word(w[o], 4)

            def unproven():
                for k, field in enumerate(RT.FIELDS):  # S15b.2: the typing program's record, rendered at its turn
                    set_work(w.add(w.add(R.TYPES_AT, w.mul(w[o], RT.RECORD_WORDS)), k), w.ld(w.add(w.add(TY.TABLE, w.mul(w[entries], field)), w[listed])))

            set_work(w.add(R.TYPES_AT, w.mul(w[o], RT.RECORD_WORDS)), 0)
            w.if_(w.both(w.either(w.eq(kind, int(Kind.TYPE)), w.eq(kind, int(Kind.CONSTANT))), w.eq(w[proven], 0), running()), unproven)
            w.set(o, w.add(w[o], 1))

        w.while_(lambda: w.lt(w[o], w[objects]), flag)

    def store_verdicts():
        """``_xax_verify_store``: the XAX store verifier's verdicts, rendered rejections, and ``verify_store``'s order."""
        results = proc.op(Operation.CALL_DIRECT, (*w.triple("vtable", w.narrowed("vtable", in_pointer)), *w.triple("image")), (B64, *VIEW_TYPES),
                          entity=verifier_program)
        w.take("vtable", results[1:4])
        w.take("image", results[4:])
        w.if_(w.ne(w.ld(0), VF.OK), lambda: stop(DECLINED))

        def plan():
            """S15b.1 (ADR-288): ``verify_store``'s order (``xax_selfhost_render``): the graphs to parse and the outcome,
            and the outcome's rendered record, kept in the workspace (the graph checks reuse the output view)."""
            count = w.let("plan_count", w.ld(R.PLAN_AT + 2))
            w.if_(w.lt(R.PLAN_LIMIT, w[count]), lambda: stop(DECLINED))
            q = w.let("plan_q", 0)
            w.while_(lambda: w.lt(w[q], w.add(w[count], 3)), lambda: (set_work(w.add(R.WORK_PLAN, w[q]), w.ld(w.add(R.PLAN_AT, w[q]))),
                                                                      w.set(q, w.add(w[q], 1))))
            index = w.let("plan_index", w.add(R.INDEX_AT, w.mul(w.ld(R.PLAN_AT + 1), R.INDEX_WORDS)))
            start, middle, end = (w.let(name, w.sel(w.both(w.eq(w.ld(R.PLAN_AT), R.P_BANK), w.ne(w.ld(R.BANK_CURSOR), 0)), w.ld(w.add(w[index], k)), 0))
                                  for k, name in enumerate(("record_start", "record_middle", "record_end")))
            w.if_(w.lt(R.RECORD_LIMIT, w.sub(w[end], w[start])), lambda: w.set(start, 0))
            w.if_(w.eq(w[start], 0), lambda: w.set(end, 0))
            set_work(R.WORK_RECORD, w.sub(w[middle], w[start]))
            set_work(R.WORK_RECORD + 1, w.sub(w[end], w[start]))
            for k in (3, 4):
                set_work(R.WORK_RECORD + k - 1, w.ld(w.add(w[index], k)))
            q2 = w.let("record_q", 0)
            w.while_(lambda: w.lt(w[q2], w.sub(w[end], w[start])), lambda: (
                set_work(w.add(R.WORK_RECORD + 4, w[q2]), w.ld(w.add(w[start], w[q2]))), w.set(q2, w.add(w[q2], 1))))

        when(plan)

    def from_work():
        """The workspace's diagnostic record (a helper function's) as the driver's."""
        end = w.let("work_end", work_word(D.DIAG_AT))
        q = w.let("work_q", D.DIAG_AT)
        w.while_(lambda: w.lt(w[q], w[end]), lambda: (w.st(w[q], work_word(w[q])), w.set(q, w.add(w[q], 1))))
        stop(REJECTED)

    def verify_outcome():
        """The plan's outcome once its graphs parsed: accepted, the rendered record, the typing program's rejection, the
        graph decoder's, or declined."""
        kind = w.let("outcome_kind", work_word(R.WORK_PLAN))
        target_object = w.let("outcome_object", work_word(R.WORK_PLAN + 1))

        def record():
            length = w.let("record_length", work_word(R.WORK_RECORD + 1))
            w.if_(w.eq(w[length], 0), lambda: stop(DECLINED))

            def write():
                D.begin(w)
                middle = w.let("record_mid", work_word(R.WORK_RECORD))
                q = w.let("record_w", 0)
                w.while_(lambda: w.lt(w[q], w[middle]), lambda: (D.put(w, work_word(w.add(R.WORK_RECORD + 4, w[q]))), w.set(q, w.add(w[q], 1))))
                mode, value = w.let("entity_mode", work_word(R.WORK_RECORD + 2)), w.let("entity_value", work_word(R.WORK_RECORD + 3))

                def of_object():
                    D.cid(w, [w.cid_word("data", record_word(w[value], 2), word) for word in range(4)])

                def missing():
                    holder, k = w.let("missing_holder", w.udiv(w[value], 1 << 32)), w.let("missing_k", w.and_(w[value], 0xFFFFFFFF))
                    D.cid(w, [w.cid_word("data", w.add(record_word(w[holder], 6), w.mul(w[k], CID_SIZE)), word) for word in range(4)])

                w.if_(w.eq(w[mode], R.ENTITY_OBJECT), of_object, lambda: w.if_(w.eq(w[mode], R.ENTITY_MISSING), missing, lambda: D.text(w, "store")))
                w.while_(lambda: w.lt(w[q], w[length]), lambda: (D.put(w, work_word(w.add(R.WORK_RECORD + 4, w[q]))), w.set(q, w.add(w[q], 1))))
                stop(REJECTED)

            when(write)

        def as_type():
            """S15b.3d (ADR-296): ``_xax_prove_as_type``: another kind of object named as a type, read by the typing
            program on its own (its body copied from the store), its record kept like a type's."""
            length = w.let("at_len", record_word(w[target_object], 8))
            body = w.let("at_body", record_word(w[target_object], 7))
            w.if_(w.lt(1 << 16, w[length]), lambda: stop(DECLINED))
            q = w.let("at_q", 0)
            w.while_(lambda: w.both(w.lt(w[q], w[length]), running()), lambda: (
                set_work(w.add(SM.OVERRIDE, w[q]), w.load("data", w.add(w[body], w[q]), 1)), w.set(q, w.add(w[q], 1))))
            set_work(SM.CTRL + SM.C_OVERRIDE, w[target_object])
            set_work(SM.CTRL + SM.C_OLEN, w[length])
            when(lambda: helper("object_marshal"))
            when(typing)

            def keep():
                entries = w.let("at_entries", work_word(SM.MARSHAL_AT))
                listed = w.let("at_listed", work_word(w.add(SM.LISTED, w[target_object])))
                for k, field in enumerate(RT.FIELDS):
                    set_work(w.add(w.add(R.TYPES_AT, w.mul(w[target_object], RT.RECORD_WORDS)), k),
                             w.sel(w.eq(w.ld(w.add(w.add(TY.TABLE, w.mul(w[entries], TY.OBJOK)), w[listed])), 1), 0,
                                   w.ld(w.add(w.add(TY.TABLE, w.mul(w[entries], field)), w[listed]))))
                # A graph's table record holds its stream, not its body: a rejection that quotes body bytes declines.
                site = work_word(w.add(R.TYPES_AT, w.mul(w[target_object], RT.RECORD_WORDS)))
                quoting = w.either(*(w.eq(site, RT.TYPE_SITE_NUMBER[name]) for name in RT.BODY_QUOTING))
                w.if_(w.both(w.eq(record_word(w[target_object], 4), int(Kind.GRAPH_FRAGMENT)), quoting), lambda: stop(DECLINED))

            when(keep)
            set_work(SM.CTRL + SM.C_OVERRIDE, FA.NONE)

        def typed():
            """S15b.2 (ADR-289): the typing program's rejection, rendered (``xax_selfhost_render_types``)."""
            kind_of = record_word(w[target_object], 4)
            w.if_(w.not_(w.either(w.eq(kind_of, int(Kind.TYPE)), w.eq(kind_of, int(Kind.CONSTANT)))), as_type)
            site = w.let("type_site", work_word(w.add(R.TYPES_AT, w.mul(w[target_object], RT.RECORD_WORDS))))

            def render():
                set_work(SM.CTRL + RT.T_OBJECT, w[target_object])
                request_helper("render", type_renderers)
                w.if_(w.eq(work_word(SM.CTRL + RT.T_STATUS), RT.ACCEPT), from_work, lambda: stop(DECLINED))

            w.if_(w.both(running(), w.ne(w[site], 0)), render, lambda: stop(DECLINED))

        def decoder():
            graph_stream(w[target_object], graph_rejected)
            when(lambda: stop(DECLINED))

        w.if_(w.eq(w[kind], R.P_BANK), record)
        w.if_(w.eq(w[kind], R.P_TYPE), typed)
        w.if_(w.eq(w[kind], R.P_DECODER), decoder)
        w.if_(w.both(running(), w.ne(w[kind], R.P_ACCEPT)), lambda: stop(DECLINED))

    def side_put(view: str, cursor: str, limit: int, value):
        w.if_(w.lt(w[cursor], limit), lambda: w.store(view, w.mul(w[cursor], 8), value, 8), lambda: stop(DECLINED))
        w.set(cursor, w.add(w[cursor], 1))

    def blk(b, field: int):
        return work_word(w.add(SM.BLK, w.add(w.mul(b, SM.BLOCK_WORDS), field)))

    def nod(n, field: int):
        return work_word(w.add(SM.NODE, w.add(w.mul(n, SM.NODE_WORDS), field)))

    if general:
        x_words, x_graphs = w.let("x_words", 0), w.let("x_graphs", 0)
        j_words, j_graphs = w.let("j_words", 0), w.let("j_graphs", 0)

    def collect(o: str):
        """S12e.2: graph ``o``'s pointer extents (``_parse_graph(...).pointer_extents``: the facts engine's when it
        accepted, by value reference) and its nonempty trap payloads' first three bytes, from the workspace's parse."""
        def xput(value):
            side_put("extents", x_words, EXTENTS_EXTENT // 8, value)

        def jput(value):
            side_put("traps", j_words, TRAPS_EXTENT // 8, value)

        for word in range(4):
            xput(w.cid_word("data", record_word(w[o], 2), word))
        x_count_at, x_count = w.let("x_count_at", w[x_words]), w.let("x_count", 0)
        xput(0)

        def extents():
            base = w.let("x_base", w.ld(FA.HEADER + FA.H_EXTENTS))

            def entry(tag: int, block, index, result, value_id):
                extent = w.let("x_extent", w.ld(w.add(w[base], value_id)))
                w.if_(w.ne(w[extent], 0), lambda: (xput(tag), xput(block), xput(index), xput(result), xput(w.sub(w[extent], 1)),
                                                   w.set(x_count, w.add(w[x_count], 1))))

            b, blocks = w.let("x_block", 0), w.let("x_blocks", work_word(SM.CTRL + SM.C_BLOCKS))

            def parameters():
                q = w.let("x_q", 0)

                def parameter():
                    entry(0, w[b], w[q], 0, w.add(blk(w[b], SM.B_BASE), w[q]))
                    w.set(q, w.add(w[q], 1))

                w.while_(lambda: w.lt(w[q], blk(w[b], SM.B_PARAMS)), parameter)
                w.set(b, w.add(w[b], 1))

            w.while_(lambda: w.lt(w[b], w[blocks]), parameters)
            n, nodes = w.let("x_node", 0), w.let("x_nodes", work_word(SM.CTRL + SM.C_NODES))

            def results():
                block = w.let("x_nb", nod(w[n], SM.N_BLOCK))
                index = w.let("x_ni", w.sub(w[n], blk(w[block], SM.B_FIRST)))
                r = w.let("x_r", 0)

                def result():
                    entry(1, w[block], w[index], w[r], w.add(nod(w[n], SM.N_BASE), w[r]))
                    w.set(r, w.add(w[r], 1))

                w.while_(lambda: w.lt(w[r], nod(w[n], SM.N_NRES)), result)
                w.set(n, w.add(w[n], 1))

            w.while_(lambda: w.lt(w[n], w[nodes]), results)

        w.if_(w.eq(w.ld(FA.HEADER + FA.H_STATUS), FA.ACCEPTED), extents)
        w.if_(w.lt(w[x_count_at], EXTENTS_EXTENT // 8), lambda: w.store("extents", w.mul(w[x_count_at], 8), w[x_count], 8))
        w.set(x_graphs, w.add(w[x_graphs], 1))

        j_start = w.let("j_start", w[j_words])
        for word in range(4):
            jput(w.cid_word("data", record_word(w[o], 2), word))
        j_count_at, j_count = w.let("j_count_at", w[j_words]), w.let("j_count", 0)
        jput(0)
        body_at = w.let("j_body", record_word(w[o], 7))
        b2, blocks2 = w.let("j_block", 0), w.let("j_blocks", work_word(SM.CTRL + SM.C_BLOCKS))

        def terminator():
            at = w.let("j_at", blk(w[b2], SM.B_TERM))
            kind = w.let("j_kind", w.load("vtable", w.mul(w[at], 8), 8))
            size = w.let("j_size", w.load("vtable", w.mul(w.add(w[at], 1), 8), 8))

            def trap():
                offset = w.let("j_offset", w.load("vtable", w.mul(w.add(w[at], 2), 8), 8))
                head = w.let("j_head", w.sel(w.lt(w[size], 3), w[size], 3))
                jput(w[b2])
                jput(w[head])
                k = w.let("j_k", 0)
                w.while_(lambda: w.lt(w[k], w[head]), lambda: (jput(w.load("data", w.add(w[body_at], w.add(w[offset], w[k])))), w.set(k, w.add(w[k], 1))))
                w.set(j_count, w.add(w[j_count], 1))

            w.if_(w.both(w.eq(w[kind], int(TerminatorKind.TRAP)), w.ne(w[size], 0)), trap)
            w.set(b2, w.add(w[b2], 1))

        w.while_(lambda: w.lt(w[b2], w[blocks2]), terminator)
        w.if_(w.eq(w[j_count], 0), lambda: w.set(j_words, w[j_start]), lambda: (
            w.if_(w.lt(w[j_count_at], TRAPS_EXTENT // 8), lambda: w.store("traps", w.mul(w[j_count_at], 8), w[j_count], 8)),
            w.set(j_graphs, w.add(w[j_graphs], 1))))

    def graph_verdicts():
        """``_parse_graph`` for the plan's graphs, in ``verify_store``'s order: CFG (branch targets, uses), then typing,
        facts, and linear flow."""
        planned = w.let("planned", 0)
        o = w.let("graph_object", 0)
        objected_ = w.let("graph_objected", 0)

        def each():
            w.set(o, work_word(w.add(R.WORK_PLAN + 3, w[planned])))
            def graph():
                set_work(SM.CTRL + SM.C_GRAPH, w[o])
                helper("parse_graph")
                when(lambda: helper("cfg_input"))

                set_work(INV_AT + I_MODE, 0)

                def run_cfg():
                    """The CFG program over the workspace's CFG input."""
                    count = w.let("c_count", work_word(SM.CTRL + SM.C_CFG_LENGTH))
                    q = w.let("q", 0)
                    w.while_(lambda: w.lt(w[q], w[count]), lambda: (w.store("cfgin", w.mul(w[q], 8), work_word(w.add(SM.CFG_AT, w[q])), 8), w.set(q, w.add(w[q], 1))))
                    results = proc.op(Operation.CALL_DIRECT, (*w.triple("cfgin", w.narrowed("cfgin", in_pointer)), *w.triple("cfgout")),
                                      (in_pointer, CF.IN_VIEW, MEM, CF.OUT_POINTER, CF.OUT_VIEW, MEM), entity=cfg_program)
                    w.take("cfgin", results[:3])
                    w.take("cfgout", results[3:])

                def cfg_word(index):
                    return w.load("cfgout", w.mul(index, 8), 8)

                def use_codes_at():
                    """The CFG output's use codes (``NativeCfg.analyze``'s layout)."""
                    n, width = work_word(SM.CTRL + SM.C_BLOCKS), cfg_word(1)
                    return w.add(w.add(w.add(67 + CF.IN_WORDS, w.mul(n, 11)), w.mul(n, width)), width)

                def each_invalid_use(body):
                    """``body(use word position)`` for each use the CFG program found invalid, in use order."""
                    uses_at = w.let("iu_uses", w.add(SM.CFG_AT, work_word(SM.CTRL + SM.C_USES)))
                    codes_at = w.let("iu_codes", use_codes_at())
                    k = w.let("iu_k", 0)

                    def step():
                        w.if_(w.ne(cfg_word(w.add(w[codes_at], w[k])), 0), lambda: body(w.add(w.add(w[uses_at], 1), w.mul(w[k], 6)), cfg_word(w.add(w[codes_at], w[k]))))
                        w.set(k, w.add(w[k], 1))

                    w.while_(lambda: w.lt(w[k], work_word(w[uses_at])), step)

                def invalid_uses():
                    """S15b.3c (ADR-295): ``_parse_graph`` with an invalid use.  The bootstrap's first pass reaches the
                    first one in its order and raises its diagnostic, unless a check before it fails first; XAX decides
                    those checks over the graph trimmed at each invalid use (until every remaining use is valid)."""
                    n = w.let("iu_n", work_word(SM.CTRL + SM.C_BLOCKS))
                    k = w.let("iu_o", 0)
                    w.while_(lambda: w.lt(w[k], w[n]), lambda: (set_work(w.add(I_ORDER, w[k]), cfg_word(w.add(3, w[k]))),
                                                              set_work(w.add(I_POSITION, cfg_word(w.add(3, w[k]))), w[k]), w.set(k, w.add(w[k], 1))))
                    best = w.let("iu_best", 1 << 63)  # no use yet

                    def first(at, code):
                        ub, un = work_word(at), work_word(w.add(at, 1))
                        key = w.let("iu_key", w.add(w.mul(work_word(w.add(I_POSITION, ub)), 1 << 32), un))

                        def keep():
                            w.set(best, w[key])
                            set_work(INV_AT + I_CODE, code)
                            for field, offset in ((I_UB, 0), (I_UN, 1), (I_TAG, 2), (I_VB, 3), (I_VI, 4), (I_VR, 5)):
                                set_work(INV_AT + field, work_word(w.add(at, offset)))

                        w.if_(w.lt(w[key], w[best]), keep)

                    each_invalid_use(first)
                    ub = w.let("iu_ub", work_word(INV_AT + I_UB))
                    set_work(INV_AT + I_POS, work_word(w.add(I_POSITION, w[ub])))
                    width = w.let("iu_width", cfg_word(1))
                    set_work(INV_AT + I_W, w[width])
                    w.if_(w.lt(1024, w[width]), lambda: stop(DECLINED))
                    d = w.let("iu_d", 0)
                    w.while_(lambda: w.both(w.lt(w[d], w[width]), running()), lambda: (
                        set_work(w.add(I_DOMS, w[d]), cfg_word(w.add(w.add(w.add(3, w[n]), w.mul(w[ub], w[width])), w[d]))), w.set(d, w.add(w[d], 1))))
                    set_work(INV_AT + I_MODE, 1)
                    # The first use's node checks its operation code before its operands (GRAPH-OP-SUPPORTED): declined.
                    un = w.let("iu_un", work_word(INV_AT + I_UN))
                    known = lambda op: w.both(w.le(1, op), w.le(op, max(int(item) for item in Operation)))  # noqa: E731
                    set_work(INV_AT + I_NODE, w.flag(w.lt(w[un], blk(w[ub], SM.B_COUNT))))  # before the trim shortens the block
                    w.if_(w.lt(w[un], blk(w[ub], SM.B_COUNT)), lambda: w.if_(
                        w.not_(known(work_word(w.add(SM.NODE, w.add(w.mul(w.add(blk(w[ub], SM.B_FIRST), w[un]), SM.NODE_WORDS), SM.N_OP))))),
                        lambda: stop(DECLINED)))
                    # Trim each block at its first invalid use until every use is valid (``trimmed``).
                    valid = w.let("iu_valid", 0)
                    rounds = w.let("iu_rounds", 0)

                    def cut(at, _code):
                        b, node = work_word(at), work_word(w.add(at, 1))
                        current = work_word(w.add(SM.CUT, b))
                        w.if_(w.either(w.eq(current, FA.NONE), w.lt(node, current)), lambda: set_work(w.add(SM.CUT, b), node))

                    def trim_round():
                        each_invalid_use(cut)
                        helper("trim")
                        when(lambda: helper("cfg_input"))
                        when(run_cfg)
                        w.if_(w.ne(cfg_word(0), CF.ACCEPT), lambda: stop(DECLINED))
                        w.set(valid, cfg_word(2))
                        w.set(rounds, w.add(w[rounds], 1))

                    w.while_(lambda: w.both(running(), w.eq(w[valid], 0), w.le(w[rounds], w[n])), trim_round)
                    w.if_(w.eq(w[valid], 0), lambda: stop(DECLINED))
                    # ``trimmed_order[:first] == native_order[:first]`` (positions before the first use's block).
                    q = w.let("iu_q", 0)
                    w.while_(lambda: w.lt(w[q], work_word(INV_AT + I_POS)), lambda: (
                        w.if_(w.ne(cfg_word(w.add(3, w[q])), work_word(w.add(I_ORDER, w[q]))), lambda: stop(DECLINED)), w.set(q, w.add(w[q], 1))))

                def cfg():
                    run_cfg()
                    status_word = w.let("c_status", w.load("cfgout", 0, 8))
                    def branch_target():
                        """S15b.3 (ADR-292): ``GRAPH-BRANCH-TARGET``, the first branch target out of range."""
                        D.begin(w)
                        D.text(w, "XAX.STRUCT.BRANCH_TARGET")
                        D.cid(w, [w.cid_word("data", record_word(w[o], 2), word) for word in range(4)])
                        D.text(w, "GRAPH-BRANCH-TARGET")
                        D.put(w, D.T_FORMAT)
                        D.text(w, "< {}")
                        D.put(w, 1)
                        D.integer(w, work_word(SM.CTRL + SM.C_BLOCKS))
                        D.integer(w, w.load("cfgout", 8, 8))
                        stop(REJECTED)

                    w.if_(w.eq(w[status_word], CF.REJECT), branch_target, lambda: w.if_(
                        w.ne(w[status_word], CF.ACCEPT), lambda: stop(DECLINED), lambda: w.if_(
                            w.eq(w.load("cfgout", 16, 8), 0), invalid_uses)))

                    def order():
                        blocks = w.let("c_blocks", work_word(SM.CTRL + SM.C_BLOCKS))
                        q2 = w.let("q", 0)
                        w.while_(lambda: w.lt(w[q2], w[blocks]), lambda: (set_work(w.add(SM.ORDER, w[q2]), w.load("cfgout", w.mul(w.add(w[q2], 3), 8), 8)),
                                                                          w.set(q2, w.add(w[q2], 1))))

                    when(order)

                when(cfg)
                when(lambda: helper("graph_marshal"))
                when(typing)

                def verdicts():
                    """S15b.3 (ADR-292): the typing program's outcome of ``_parse_graph`` in its order
                    (``xax_selfhost_render_graph``): accepted, its rendered rejection, or a decline."""
                    status = w.let("g_outcome", w.ld(RG.OUTCOME_AT + RG.O_STATUS))

                    def rejected():
                        D.begin(w)
                        end = w.let("g_end", w.ld(RG.OUTCOME_AT + RG.O_CURSOR))
                        code_end = w.let("g_code_end", w.add(RG.RECORD_AT, w.add(2, w.udiv(w.add(w.ld(RG.RECORD_AT + 1), 7), 8))))
                        q = w.let("g_q", RG.RECORD_AT)
                        w.while_(lambda: w.lt(w[q], w[code_end]), lambda: (D.put(w, w.ld(w[q])), w.set(q, w.add(w[q], 1))))
                        w.if_(w.eq(w.ld(RG.OUTCOME_AT + RG.O_ENTITY), RG.ENTITY_GRAPH),
                              lambda: D.cid(w, [w.cid_word("data", record_word(w[o], 2), word) for word in range(4)]))
                        w.while_(lambda: w.lt(w[q], w[end]), lambda: (D.put(w, w.ld(w[q])), w.set(q, w.add(w[q], 1))))
                        stop(REJECTED)

                    def render_use():
                        """``value_type``'s diagnostic for the first invalid use (the CFG program's code)."""
                        code = w.let("ru_code", work_word(INV_AT + I_CODE))
                        vb, vi, vr = (work_word(INV_AT + field) for field in (I_VB, I_VI, I_VR))
                        D.begin(w)
                        w.if_(w.eq(w[code], 1), lambda: D.text(w, "XAX.STRUCT.VALUE_BLOCK"), lambda: w.if_(
                            w.le(w[code], 3), lambda: D.text(w, "XAX.STRUCT.VALUE_INDEX"), lambda: D.text(w, "XAX.STRUCT.SSA_DOMINANCE")))
                        D.cid(w, [w.cid_word("data", record_word(w[o], 2), word) for word in range(4)])
                        w.if_(w.le(w[code], 3), lambda: D.text(w, "GRAPH-VALUE-DEFINED"), lambda: D.text(w, "GRAPH-SSA-DOMINANCE"))

                        def less_than(bound):
                            D.put(w, D.T_FORMAT)
                            D.text(w, "< {}")
                            D.put(w, 1)
                            D.integer(w, bound)

                        def dominators():
                            """``sorted(dominators[use_block])``: the saved bitset's blocks, ascending."""
                            n = w.let("ru_n", work_word(SM.CTRL + SM.C_BLOCKS))

                            def each(emit):
                                b, mask = w.let("ru_b", 0), w.let("ru_mask", 1)

                                def step():
                                    w.if_(w.ne(w.and_(work_word(w.add(I_DOMS, w.udiv(w[b], 64))), w[mask]), 0), lambda: emit(w[b]))
                                    w.set(mask, w.sel(w.eq(w.and_(w[b], 63), 63), 1, w.mul(w[mask], 2)))
                                    w.set(b, w.add(w[b], 1))

                                w.while_(lambda: w.lt(w[b], w[n]), step)

                            total = w.let("ru_count", 0)
                            each(lambda _b: w.set(total, w.add(w[total], 1)))
                            D.put(w, D.T_LIST)
                            D.put(w, w[total])
                            each(lambda b: D.integer(w, b))

                        w.if_(w.eq(w[code], 1), lambda: (less_than(work_word(SM.CTRL + SM.C_BLOCKS)), D.integer(w, vb)))
                        w.if_(w.eq(w[code], 2), lambda: (less_than(blk(vb, SM.B_PARAMS)), D.integer(w, vi)))
                        w.if_(w.eq(w[code], 3), lambda: (D.text(w, "existing node result"), D.put(w, D.T_LIST), D.put(w, 2), D.integer(w, vi), D.integer(w, vr)))
                        w.if_(w.eq(w[code], 4), lambda: (D.put(w, D.T_FORMAT), D.text(w, "node < {}"), D.put(w, 1), D.integer(w, work_word(INV_AT + I_UN)),
                                                         D.integer(w, vi)))
                        w.if_(w.eq(w[code], 5), lambda: (dominators(), D.integer(w, vb)))
                        stop(REJECTED)

                    def trimmed():
                        """S15b.3c: the trimmed graph's outcome counts only before the first invalid use; after it, the
                        bootstrap reached the use.  At the use's own node (S15b.3d) the use comes first: a node's operands
                        resolve right after its operation code (declined above), before its memory and typing checks; at a
                        terminator the trimmed graph's trap has other checks (declined)."""
                        here = w.let("g_here", w.ld(RG.OUTCOME_AT + RG.O_POS))
                        first = w.let("g_first", w.add(w.mul(work_word(INV_AT + I_POS), 1 << 32), work_word(INV_AT + I_UN)))
                        decided = w.either(w.eq(w[status], RG.G_REJECT), w.eq(w[status], RG.G_OBJECT))
                        reached = w.either(w.lt(w[first], w[here]), w.both(decided, w.eq(w[first], w[here]), w.ne(work_word(INV_AT + I_NODE), 0)))
                        w.if_(w.both(decided, w.lt(w[here], w[first])), lambda: w.if_(w.eq(w[status], RG.G_REJECT), rejected, objected), lambda: w.if_(
                            w.either(w.eq(w[status], RG.G_ACCEPT), reached), render_use, lambda: stop(DECLINED)))

                    def objected():
                        """S15b.3d (ADR-297): another object's own rejection decides (``RG.G_OBJECT``): the plan's outcome
                        becomes that object's typing record (``P_TYPE``), after this graph."""
                        entry_ = w.ld(RG.OUTCOME_AT + RG.O_ENTITY)
                        set_work(R.WORK_PLAN + 1, work_word(w.add(SM.ENT, w.mul(entry_, SM.ENTRY_WORDS))))
                        set_work(R.WORK_PLAN, R.P_TYPE)
                        w.set(planned, work_word(R.WORK_PLAN + 2))
                        w.set(objected_, 1)

                    w.if_(w.ne(work_word(INV_AT + I_MODE), 0), trimmed, lambda: w.if_(w.eq(w[status], RG.G_REJECT), rejected, lambda: w.if_(
                        w.eq(w[status], RG.G_OBJECT), objected, lambda: w.if_(w.ne(w[status], RG.G_ACCEPT), lambda: stop(DECLINED)))))

                when(verdicts)
                if general:
                    when(lambda: w.if_(w.eq(w[objected_], 0), lambda: collect(o)))

            w.if_(w.eq(record_word(w[o], 4), int(Kind.GRAPH_FRAGMENT)), graph, lambda: stop(DECLINED))
            w.set(planned, w.add(w[planned], 1))

        w.while_(lambda: w.both(w.lt(w[planned], work_word(R.WORK_PLAN + 2)), running()), each)

    when(object_table)
    when(object_verdicts)
    when(store_verdicts)
    when(graph_verdicts)
    when(verify_outcome)
    if general:
        # -- S13a (ADR-281): ``build``: the snapshot's request, read and checked by ``xax_selfhost_request`` ---------
        target, linux = w.let("target", 0), w.let("linux", 0)

        def inputs_to_work():
            """S15c.2: the input digests, one byte per word, at ``INPUTS_AT`` of the workspace; their count."""
            q = w.let("iw", 0)
            w.while_(lambda: w.lt(w[q], w.mul(w[inputs_count], CID_SIZE)), lambda: (
                set_work(w.add(RQ.INPUTS_AT, w[q]), w.load("inputs", w[q])), w.set(q, w.add(w[q], 1))))
            set_work(SM.CTRL + RQ.B_INPUTS, w[inputs_count])

        def build_request():
            inputs_to_work()
            request_helper("build_request")
            outcome = w.let("request_outcome", work_word(SM.CTRL + RQ.B_STATUS))
            w.if_(w.eq(w[outcome], RQ.REJECT), from_work, lambda: w.if_(w.ne(w[outcome], RQ.ACCEPT), lambda: stop(DECLINED)))
            w.set(entry, work_word(SM.CTRL + RQ.B_ENTRY))
            w.set(target, work_word(SM.CTRL + RQ.B_TARGET))
            w.set(linux, 1)

        when(lambda: w.if_(w.eq(w[mode], BUILD), build_request))

        # -- S13c (ADR-283): ``resolve``: the request store's packages selected, the snapshot store written ---------
        resolved = w.let("resolved", 0)  # the snapshot store's length in ``written``

        def batch_put(at: str, value):
            w.store("batch", w[at], value, 8)
            w.set(at, w.add(w[at], 8))

        def batch_copy(at: str, source: str, source_at, count):
            w.copy(source, source_at, "batch", w[at], count)
            w.set(at, w.add(w[at], count))

        def hash_preimage(count, cid_at: int):
            """The S2 hash of the domain and ``object[domain:]``; the CID in ``argument[cid_at:]``."""
            for k, byte in enumerate(SEMANTIC_DOMAIN):
                w.store("object", k, byte)
            hash_span("object", 0, w.add(len(SEMANTIC_DOMAIN), count))
            digest_to("argument", cid_at)

        def snapshot_store():
            """The policy's CID (``argument[0:32]``), the snapshot's (``argument[32:64]``), the writer's batch: the
            request store's objects, the policy, the snapshot; the store the S9 writer makes."""
            for k, byte in enumerate(RS.POLICY_PREIMAGE):
                w.store("object", len(SEMANTIC_DOMAIN) + k, byte)
            hash_preimage(len(RS.POLICY_PREIMAGE), 0)
            for k in range(4):
                set_work(SM.CTRL + RS.R_POLICY + k, w.cid_word("argument", 0, k))
            request_helper("snapshot", resolvers)
            length = w.let("snapshot_length", work_word(SM.CTRL + RS.R_LENGTH))
            w.if_(w.lt(RS.SNAPSHOT_LIMIT, w[length]), lambda: capacity("snapshot", "DRIVER-SNAPSHOT-CAPACITY", RS.SNAPSHOT_LIMIT))

            def batch():
                q = w.let("s_q", 0)
                w.while_(lambda: w.lt(w[q], w[length]), lambda: (
                    w.store("object", w.add(len(SEMANTIC_DOMAIN), w[q]), work_word(w.add(RS.SNAPSHOT_AT, w[q]))), w.set(q, w.add(w[q], 1))))
                hash_preimage(w[length], CID_SIZE)

                def grant_rejected():
                    """S15c.1 (ADR-299): ``decode_snapshot`` rejects a profile grant no selected package declares."""
                    for k in range(4):
                        set_work(SM.CTRL + RS.R_SNAPSHOT_CID + k, w.cid_word("argument", CID_SIZE, k))
                    request_helper("grant_record", resolvers)
                    from_work()

                w.if_(w.ne(work_word(SM.CTRL + RS.R_GRANT), RS.NO_GRANT), grant_rejected)
                at = w.let("b_at", 24)
                batch_copy(at, "argument", CID_SIZE, CID_SIZE)  # the root: the snapshot
                o = w.let("b_object", 0)

                def each():
                    count, size = w.let("b_refs", record_word(w[o], 5)), w.let("b_body", record_word(w[o], 8))
                    w.if_(w.lt(WR.IN_EXTENT - 4096, w.add(w[at], w.add(w.mul(w[count], CID_SIZE), w[size]))),
                          lambda: capacity("snapshot", "DRIVER-SNAPSHOT-CAPACITY", WR.IN_EXTENT - 4096), lambda: (
                        batch_put(at, record_word(w[o], 4)), batch_put(at, 1), batch_put(at, w[count]), batch_put(at, w[size]),
                        batch_copy(at, "data", record_word(w[o], 2), CID_SIZE), batch_copy(at, "data", record_word(w[o], 6), w.mul(w[count], CID_SIZE)),
                        batch_copy(at, "data", record_word(w[o], 7), w[size])))
                    w.set(o, w.add(w[o], 1))

                w.while_(lambda: w.both(w.lt(w[o], w[objects]), running()), each)

                def tail():
                    for value in (int(Kind.BUILD), 1, 0, len(RS.POLICY.body)):
                        batch_put(at, value)
                    batch_copy(at, "argument", 0, CID_SIZE)
                    for byte in RS.POLICY.body:
                        w.store("batch", w[at], byte)
                        w.set(at, w.add(w[at], 1))
                    references, body = (w.let(name, work_word(SM.CTRL + field)) for name, field in (("b_refs_at", RS.R_REFS_AT), ("b_body_at", RS.R_BODY_AT)))
                    count, size = w.let("b_count", w.add(work_word(SM.CTRL + RS.R_PACKAGES), 2)), w.let("b_size", work_word(SM.CTRL + RS.R_BODY_LENGTH))
                    for value in (int(Kind.BUILD), 1, w[count], w[size]):
                        batch_put(at, value)
                    batch_copy(at, "argument", CID_SIZE, CID_SIZE)
                    batch_copy(at, "object", w.add(len(SEMANTIC_DOMAIN), w[references]), w.mul(w[count], CID_SIZE))
                    batch_copy(at, "object", w.add(len(SEMANTIC_DOMAIN), w[body]), w[size])
                    for field, value in enumerate((w.add(w[objects], 2), 0, w[at])):
                        w.store("batch", 8 * field, value, 8)
                    results = proc.op(Operation.CALL_DIRECT, (*w.triple("batch", w.narrowed("batch", WR.BATCH_POINTER)), *w.triple("written"),
                                                              *w.triple("scratch"), w.c(WR.MODE_WRITE)), tuple(type_ for _name, type_ in WR.VIEWS),
                                      entity=writer)
                    w.take("batch", results[:3])
                    w.take("written", results[3:6])
                    w.take("scratch", results[6:])
                    w.if_(w.ne(w.load("written", WR.STATUS_AT, 8), WR.ACCEPT), lambda: stop(DECLINED),
                          lambda: w.set(resolved, w.load("written", WR.STATUS_AT + 24, 8)))

                when(tail)

            when(batch)

        def resolve():
            inputs_to_work()
            request_helper("select", resolvers)
            outcome = w.let("select_outcome", work_word(SM.CTRL + RS.R_STATUS))
            w.if_(w.eq(w[outcome], RS.REJECT), from_work, lambda: w.if_(w.ne(w[outcome], RS.ACCEPT), lambda: stop(DECLINED)))
            when(snapshot_store)

        when(lambda: w.if_(w.eq(w[mode], RESOLVE), resolve))
        when(lambda: w.if_(w.le(VERIFY, w[mode]), lambda: stop(DONE)))  # S13b, S13c: these commands end here

    # -- the backend's object table (``xax_riscv64._object_table``) -----------------------------------------------
    words = w.let("words", 1 + 4)
    table_limit = in_view_extent(in_view) // 8

    def put(value):
        w.if_(w.lt(w[words], table_limit), lambda: w.store("table", w.mul(w[words], 8), value, 8), lambda: stop(DECLINED))
        w.set(words, w.add(w[words], 1))

    def put_cid(view: str, at):
        for word in range(4):
            put(w.cid_word(view, at, word))

    def table_header():
        w.store("table", 0, w[objects], 8)
        for word in range(4):
            w.store("table", 8 * (1 + word), w.cid_word("data", record_word(w[entry], 2), word), 8)

    when(table_header)

    def table_object(position):
        kind, references = w.let("kind", record_word(position, 4)), w.let("references", record_word(position, 5))
        put(w[kind])
        put(w[references])
        r = w.let("ref", 0)
        w.while_(lambda: w.lt(w[r], w[references]), lambda: (put_cid("data", w.add(record_word(position, 6), w.mul(w[r], CID_SIZE))), w.set(r, w.add(w[r], 1))))
        put_cid("data", record_word(position, 2))
        body_at, body_length = w.let("body_at", record_word(position, 7)), w.let("body_length", record_word(position, 8))

        def graph():
            w.if_(w.lt(G.BODY_EXTENT - CID_SIZE, w[body_length]), lambda: stop(DECLINED))

            def stream():
                w.copy("data", w[body_at], "body", 0, w[body_length])
                w.copy("data", record_word(position, 2), "body", w[body_length], CID_SIZE)
                results = proc.op(Operation.CALL_DIRECT, (*w.triple("body", w.narrowed("body", G.BODY_POINTER)), *w.triple("stream"), w[body_length],
                                                          w[references]), (G.BODY_POINTER, G.BODY_VIEW, MEM, G.OUT_POINTER, G.OUT_VIEW, MEM),
                                  entity=graph_decoder)
                w.take("body", results[:3])
                w.take("stream", results[3:])
                code = w.let("graph_status", w.load("stream", 0, 8))

                def accepted():
                    count = w.let("stream_words", w.sub(w.load("stream", 8, 8), 2))
                    put(w[count])
                    q = w.let("q", 0)
                    w.while_(lambda: w.both(w.lt(w[q], w[count]), running()), lambda: (put(w.load("stream", w.mul(w.add(w[q], 2), 8), 8)), w.set(q, w.add(w[q], 1))))

                def rejected():
                    end = w.let("graph_end", w.load("stream", 8 * G.DIAG_AT, 8))
                    q, n = w.let("gq", G.DIAG_AT + 1), w.let("gn", D.DIAG_AT + 1)
                    w.while_(lambda: w.lt(w[q], w[end]), lambda: (w.st(w[n], w.load("stream", w.mul(w[q], 8), 8)), w.set(q, w.add(w[q], 1)),
                                                                 w.set(n, w.add(w[n], 1))))
                    w.st(D.DIAG_AT, w[n])
                    stop(REJECTED)

                w.if_(w.eq(w[code], 0), accepted, lambda: w.if_(w.eq(w[code], 1), rejected, lambda: stop(DECLINED)))

            when(stream)

        def plain():
            put(w[body_length])
            q = w.let("q", 0)
            w.while_(lambda: w.both(w.lt(w[q], w[body_length]), running()), lambda: (put(w.load("data", w.add(w[body_at], w[q]))), w.set(q, w.add(w[q], 1))))

        w.if_(w.eq(w[kind], int(Kind.GRAPH_FRAGMENT)), graph, plain)

    k2 = w.let("listed", 0)
    w.while_(lambda: w.both(w.lt(w[k2], w[objects]), running()), lambda: (table_object(w[k2]), w.set(k2, w.add(w[k2], 1))))

    if general:
        m_words, m_count = w.let("m_words", 0), w.let("m_count", 0)

    def group_members():
        """``general_object_table``'s group member functions (``group_member_function``: kind FUNCTION, the group as
        its one reference, body ``uleb(0) uleb(member)``) the store does not hold, each CID derived with the S2 hash;
        in store order, then member order."""
        def mput(value):
            side_put("members", m_words, MEMBERS_EXTENT // 8, value)

        g = w.let("m_group", 0)
        base = len(SEMANTIC_DOMAIN)
        body_at = base + 3 + CID_SIZE  # the body's length byte; the body follows
        cid_at = w.let("m_cid_at", w.add(w[length], CID_SIZE))  # past the container digest (``limit`` keeps room)

        def each():
            def group():
                at = w.let("m_at", record_word(w[g], 7))
                count, shift, more = w.let("m_n", 0), w.let("m_shift", 1), w.let("m_more", 1)

                def byte():
                    value = w.let("m_byte", w.load("data", w[at]))
                    w.set(count, w.add(w[count], w.mul(w.and_(w[value], 127), w[shift])))
                    w.set(shift, w.mul(w[shift], 128))
                    w.set(more, w.flag(w.le(128, w[value])))
                    w.set(at, w.add(w[at], 1))

                w.while_(lambda: w.ne(w[more], 0), byte)
                m = w.let("m_member", 0)

                def member():
                    for k, data_byte in enumerate(SEMANTIC_DOMAIN):
                        w.store("object", k, data_byte)
                    for k, data_byte in enumerate((int(Kind.FUNCTION), 1, 1)):  # kind, schema version, one reference
                        w.store("object", base + k, data_byte)
                    w.copy("data", record_word(w[g], 2), "object", base + 3, CID_SIZE)
                    w.store("object", body_at + 1, 0)
                    n, v, first = w.let("m_length", 1), w.let("m_v", w[m]), w.let("m_first", 1)

                    def encode():
                        low = w.let("m_low", w.urem(w[v], 128))
                        w.set(v, w.udiv(w[v], 128))
                        w.store("object", w.add(body_at + 1, w[n]), w.add(w[low], w.mul(w.flag(w.ne(w[v], 0)), 128)))
                        w.set(n, w.add(w[n], 1))
                        w.set(first, 0)

                    w.while_(lambda: w.either(w.ne(w[first], 0), w.ne(w[v], 0)), encode)
                    w.store("object", body_at, w[n])
                    hash_span("object", 0, w.add(body_at + 1, w[n]))
                    digest_to("data", w[cid_at])
                    found = find(w[cid_at])

                    def extra():
                        mput(int(Kind.FUNCTION))
                        mput(1)
                        for word in range(4):
                            mput(w.cid_word("data", record_word(w[g], 2), word))
                        for word in range(4):
                            mput(w.cid_word("data", w[cid_at], word))
                        mput(w[n])
                        q = w.let("m_q", 0)
                        w.while_(lambda: w.lt(w[q], w[n]), lambda: (mput(w.load("object", w.add(body_at + 1, w[q]))), w.set(q, w.add(w[q], 1))))
                        w.set(m_count, w.add(w[m_count], 1))

                    w.if_(w.eq(w[found], w[objects]), extra)
                    w.set(m, w.add(w[m], 1))

                w.while_(lambda: w.both(w.lt(w[m], w[count]), running()), member)

            w.if_(w.eq(record_word(w[g], 4), int(Kind.RECURSION_GROUP)), group)
            w.set(g, w.add(w[g], 1))

        w.while_(lambda: w.both(w.lt(w[g], w[objects]), running()), each)

    if general:
        when(group_members)

    # -- the target package: its root object, checked like any object, then appended ----------------------------
    def target_store():
        read_store(1)
        when(decode_container)
        when(lambda: w.set(objects, w.load("decoded", 8, 4)))

    if not general:
        target_store()
        target = w.let("target", 0)  # (the general driver's is declared with its build section)

    def target_record():
        w.set(target, w[find(w.load("decoded", 4 * 7, 4))])
        w.if_(w.eq(w[target], w[objects]), lambda: stop(DECLINED))
        when(lambda: check_object(w[target]))

    if not general:
        when(target_record)

    executable = w.let("executable", 0)  # S11: the target is the exec profile: the output is an ELF executable

    def target_profile():
        """``compile_x86_64_views``: a target object whose identity is a views profile, else ``X86_64_VIEWS-TARGET-PROFILE``."""
        w.if_(w.ne(record_word(w[target], 4), int(Kind.TARGET)), lambda: stop(DECLINED))
        body = w.let("target_body", record_word(w[target], 7))
        size = w.let("identity", w.load("data", w[body]))  # one ULEB byte: identities are shorter than 128 bytes
        w.if_(w.le(128, w[size]), lambda: stop(DECLINED))
        start = w.let("identity_at", w.add(w[body], 1))
        known = w.let("known", 0)
        w.if_(w.eq(w[size], len(EXEC_IDENTITY)), lambda: w.set(executable, w.same_constant("data", w[start], EXEC_IDENTITY)))
        for identity in VIEWS_IDENTITIES:
            w.if_(w.eq(w[size], len(identity)), lambda identity=identity: w.set(known, w.or_(w[known], w.same_constant("data", w[start], identity))))
        if general:
            for identity in GENERAL_IDENTITIES:
                w.if_(w.eq(w[size], len(identity)), lambda identity=identity: w.set(linux, w.or_(w[linux], w.same_constant("data", w[start], identity))))
            w.set(known, w.or_(w[known], w[linux]))
        printable = w.let("printable", 1)
        q = w.let("q", 0)
        w.while_(lambda: w.lt(w[q], w[size]), lambda: (w.set(printable, w.and_(w[printable], w.flag(w.both(
            w.le(32, w.load("data", w.add(w[start], w[q]))), w.lt(w.load("data", w.add(w[start], w[q])), 127))))), w.set(q, w.add(w[q], 1))))

        def reject():
            D.begin(w)
            D.text(w, "XAX.X86_64_VIEWS.TARGET")
            D.cid(w, [w.cid_word("data", record_word(w[target], 2), word) for word in range(4)])
            D.text(w, "X86_64_VIEWS-TARGET-PROFILE")
            D.text(w, VIEWS_IDENTITIES[0].decode())
            D.put(w, D.T_STR)
            D.put(w, w[size])
            packed = w.let("packed", 0)
            q2 = w.let("byte", 0)

            def pack():
                shift = w.let("shift", 1)
                r = w.let("r", 0)
                w.while_(lambda: w.lt(w[r], w.urem(w[q2], 8)), lambda: (w.set(shift, w.mul(w[shift], 256)), w.set(r, w.add(w[r], 1))))
                w.set(packed, w.add(w[packed], w.mul(w.load("data", w.add(w[start], w[q2])), w[shift])))
                w.if_(w.either(w.eq(w.urem(w[q2], 8), 7), w.eq(w.add(w[q2], 1), w[size])), lambda: (D.put(w, w[packed]), w.set(packed, 0)))
                w.set(q2, w.add(w[q2], 1))

            w.while_(lambda: w.lt(w[q2], w[size]), pack)
            stop(REJECTED)

        w.if_(w.ne(w[known], 0), lambda: None, lambda: w.if_(w.ne(w[printable], 0), reject, lambda: stop(DECLINED)))

    if general:
        def target_package():
            """``lower``: the target package's root (S12e.2's ``linux`` flag: the general backend lowers)."""
            target_store()
            when(target_record)
            when(target_profile)

        when(lambda: w.if_(w.eq(w[mode], LOWER), target_package))
    else:
        when(target_profile)

    def target_entry():
        position = w[target]
        put(record_word(position, 4))
        put(record_word(position, 5))
        r = w.let("target_ref", 0)
        w.while_(lambda: w.lt(w[r], record_word(position, 5)), lambda: (put_cid("data", w.add(record_word(position, 6), w.mul(w[r], CID_SIZE))), w.set(r, w.add(w[r], 1))))
        put_cid("data", record_word(position, 2))
        body_at, body_length = w.let("tbody_at", record_word(position, 7)), w.let("tbody_length", record_word(position, 8))
        put(w[body_length])
        q = w.let("q", 0)
        w.while_(lambda: w.lt(w[q], w[body_length]), lambda: (put(w.load("data", w.add(w[body_at], w[q]))), w.set(q, w.add(w[q], 1))))

    when(target_entry)

    def general_sections():
        """``general_object_table`` after the target: the group member functions the store does not hold, the pointer
        extents, no audit, and the trap payload heads."""
        put(w[m_count])
        q0 = w.let("m_copy", 0)
        w.while_(lambda: w.both(w.lt(w[q0], w[m_words]), running()), lambda: (put(w.load("members", w.mul(w[q0], 8), 8)), w.set(q0, w.add(w[q0], 1))))
        put(w[x_graphs])
        q = w.let("x_copy", 0)
        w.while_(lambda: w.both(w.lt(w[q], w[x_words]), running()), lambda: (put(w.load("extents", w.mul(w[q], 8), 8)), w.set(q, w.add(w[q], 1))))
        put(0)
        put(w[j_graphs])
        q2 = w.let("j_copy", 0)
        w.while_(lambda: w.both(w.lt(w[q2], w[j_words]), running()), lambda: (put(w.load("traps", w.mul(w[q2], 8), 8)), w.set(q2, w.add(w[q2], 1))))

    if general:
        when(lambda: w.if_(w.ne(w[linux], 0), general_sections))

    # -- the backend -------------------------------------------------------------------------------------------
    def lower():
        def call(program):
            results = proc.op(Operation.CALL_DIRECT, (*w.triple("table", w.narrowed("table", in_pointer)), *w.triple("image")), (B64, *VIEW_TYPES),
                              entity=program)
            w.take("table", results[1:4])
            w.take("image", results[4:])

        if general:
            w.if_(w.ne(w[linux], 0), lambda: call(general_program), lambda: call(backend))
        else:
            call(backend)
        code = w.let("backend_status", w.ld(0))
        w.if_(w.eq(w[code], 1), lambda: None, lambda: w.if_(w.eq(w[code], D.REJECT), lambda: stop(REJECTED), lambda: stop(DECLINED)))
        if general:
            # The general program decided the closure but not every function's code: the bootstrap would assemble.
            w.if_(w.both(running(), w.ne(w[linux], 0), w.ne(w.ld(GI.IMAGE_AT), 1)), lambda: stop(DECLINED))

    when(lower)

    if general:
        def elf_at():
            """S12e.2: the word holding the byte length of the ELF file in the general program's image record (status,
            packed code, packed ELF); the file's words follow it."""
            return w.let("elf_at", w.add(GI.IMAGE_AT + 2, w.udiv(w.add(w.ld(GI.IMAGE_AT + 1), 7), 8)))

        def provenance():
            """The artifact's digest (S2 hash) for ``provenance``'s envelope, copied to ``argument``; its CID derived
            with the S2 hash from the domain and the envelope from its kind on."""
            at = elf_at()
            size = w.let("artifact_size", w.ld(w[at]))
            w.if_(w.lt(limit, w[size]), lambda: stop(DECLINED))  # the hash reads its last block past the end

            def record():
                q = w.let("p_q", 0)
                w.while_(lambda: w.lt(w[q], w[size]), lambda: (w.store("object", w[q], w.ld(w.add(w.add(w[at], 1), w.udiv(w[q], 8))), 8),
                                                               w.set(q, w.add(w[q], 8))))
                hash_span("object", 0, w[size])
                for word in range(CID_SIZE // 8):
                    low, high = (w.load("scratch", H.DIGEST_OFFSET + 8 * word + 4 * half, 4) for half in (0, 1))
                    set_work(SM.CTRL + RQ.B_DIGEST + word, w.add(low, w.mul(high, 1 << 32)))
                request_helper("provenance")
                q2 = w.let("p_q", 0)
                w.while_(lambda: w.lt(w[q2], len(RQ.TEMPLATE)), lambda: (w.store("argument", w[q2], work_word(w.add(RQ.ENVELOPE_AT, w[q2]))),
                                                                         w.set(q2, w.add(w[q2], 1))))
                for k, byte in enumerate(SEMANTIC_DOMAIN):
                    w.store("object", k, byte)
                w.copy("argument", RQ.P_KIND, "object", len(SEMANTIC_DOMAIN), len(RQ.TEMPLATE) - RQ.P_KIND)
                hash_span("object", 0, len(SEMANTIC_DOMAIN) + len(RQ.TEMPLATE) - RQ.P_KIND)
                digest_to("argument", RQ.P_CID)

            when(record)

        def built():
            """``build`` checks the requested artifacts after making the container."""
            w.if_(w.ne(work_word(SM.CTRL + RQ.B_ARTIFACT), 0), from_work, provenance)

        when(lambda: w.if_(w.eq(w[mode], BUILD), built))

    # -- the output ------------------------------------------------------------------------------------------
    def write_chunk(fd: str, count):
        """``write`` the first ``count`` bytes of ``chunk``; FAILED unless all are written."""
        written, w.p["fs"], w.p[views["chunk"][2]] = w.syscall(WRITE_RW, (fd32(fd), w.p[views["chunk"][0]], count, w.p["fs"], w.p[views["chunk"][2]]),
                                                               (B64, FS, MEM))
        ok = w.let("written_ok", w.flag(w.eq(written, count)))
        w.if_(w.eq(w[ok], 0), lambda: stop(FAILED))
        return w[ok]

    def emit(first_word, byte_count, header: bool = False, path: int = 2):
        """Write ``byte_count`` bytes of the backend output from word ``first_word`` (little-endian words: the packed
        code, ADR-266, or a diagnostic record) to the file argument ``path``; with ``header``, under the exec profile,
        the ELF header first."""
        fd = open_path(path, O_OUTPUT, MODE_OUTPUT, guard=lambda: w.ne(w[status], FAILED))

        def elf_header():
            """S11: ``views_executable``'s header; only the load segment's file and memory sizes depend on the code."""
            for index, word in enumerate(ELF_HEADER_WORDS):
                w.store("chunk", 8 * index, w.add(byte_count, ELF_HEADER_SIZE) if index in ELF_SIZE_WORDS else word, 8)
            write_chunk(fd, ELF_HEADER_SIZE)

        def write_all():
            if header:
                w.if_(w.ne(w[executable], 0), elf_header)
            done = w.let("done", 0)
            total = w.let("total", byte_count)

            def step():
                piece = w.let("piece", w.sel(w.lt(w.sub(w[total], w[done]), CHUNK), w.sub(w[total], w[done]), CHUNK))
                q = w.let("q", 0)
                w.while_(lambda: w.lt(w[q], w[piece]), lambda: (w.store("chunk", w[q], w.ld(w.add(first_word, w.udiv(w.add(w[done], w[q]), 8))), 8),
                                                                w.set(q, w.add(w[q], 8))))
                w.if_(w.eq(write_chunk(fd, w[piece]), 0), lambda: w.set(done, w[total]), lambda: w.set(done, w.add(w[done], w[piece])))

            w.while_(lambda: w.both(w.lt(w[done], w[total]), w.ne(w[status], FAILED)), step)
            close(fd)

        w.if_(w.ne(w[status], FAILED), write_all)

    from xax_selfhost_views_backend import WORDS_AT

    final = w.let("final", 0)
    w.set(final, w[status])
    def image_out():
        def elf(path: int):
            """S12e.2: the ELF file of the general program's image record."""
            at = elf_at()
            emit(w.add(w[at], 1), w.ld(w[at]), path=path)

        def provenance_out():
            """S13a: the provenance object's envelope to the third file argument."""
            fd = open_path(2, O_OUTPUT, MODE_OUTPUT, guard=lambda: w.ne(w[status], FAILED))

            def write():
                w.copy("argument", 0, "chunk", 0, len(RQ.TEMPLATE))
                write_chunk(fd, len(RQ.TEMPLATE))
                close(fd)

            w.if_(w.ne(w[status], FAILED), write)

        if general:
            w.if_(w.ne(w[linux], 0), lambda: w.if_(w.eq(w[mode], BUILD), lambda: (elf(1), provenance_out()), lambda: elf(2)),
                  lambda: emit(WORDS_AT, w.ld(1), header=True))
        else:
            emit(WORDS_AT, w.ld(1), header=True)

    def record_out():
        """The rejection's diagnostic record, to the output (``build``: the artifact's file)."""
        def to(path: int):
            emit(D.DIAG_AT + 1, w.mul(w.sub(w.ld(D.DIAG_AT), D.DIAG_AT + 1), 8), path=path)

        if general:
            w.if_(w.eq(w[mode], LOWER), lambda: to(2), lambda: to(1))
        else:
            to(2)

    w.if_(w.eq(w[status], IMAGE), image_out, lambda: w.if_(w.eq(w[status], REJECTED), record_out))
    if general:
        def done_out():
            """S13b: ``verify`` writes nothing (an empty file); ``inspect`` the store's root, then per object its kind,
            its CID, and its references' CIDs (``decode_inspection``)."""
            def inspect_record():
                n = w.let("i_at", INSPECT_AT)

                def put(value):
                    w.st(w[n], value)
                    w.set(n, w.add(w[n], 1))

                def cid(at):
                    for word in range(4):
                        put(w.cid_word("data", at, word))

                cid(w.load("decoded", 4 * 7, 4))
                put(w[objects])
                o = w.let("i_object", 0)

                def each():
                    put(record_word(w[o], 4))
                    count = w.let("i_references", record_word(w[o], 5))
                    put(w[count])
                    cid(record_word(w[o], 2))
                    r = w.let("i_reference", 0)
                    w.while_(lambda: w.lt(w[r], w[count]), lambda: (cid(w.add(record_word(w[o], 6), w.mul(w[r], CID_SIZE))), w.set(r, w.add(w[r], 1))))
                    w.set(o, w.add(w[o], 1))

                w.while_(lambda: w.lt(w[o], w[objects]), each)
                emit(INSPECT_AT, w.mul(w.sub(w[n], INSPECT_AT), 8), path=1)

            def resolved_store():
                """S13c: the snapshot store, ``written[0:resolved]``."""
                fd = open_path(1, O_OUTPUT, MODE_OUTPUT, guard=lambda: w.ne(w[status], FAILED))
                done = w.let("r_done", 0)

                def step():
                    piece = w.let("r_piece", w.sel(w.lt(w.sub(w[resolved], w[done]), CHUNK), w.sub(w[resolved], w[done]), CHUNK))
                    w.copy("written", w[done], "chunk", 0, w[piece])
                    w.if_(w.eq(write_chunk(fd, w[piece]), 0), lambda: w.set(done, w[resolved]), lambda: w.set(done, w.add(w[done], w[piece])))

                def write():
                    w.while_(lambda: w.lt(w[done], w[resolved]), step)
                    close(fd)

                w.if_(w.ne(w[status], FAILED), write)

            w.if_(w.eq(w[mode], INSPECT), inspect_record, lambda: w.if_(w.eq(w[mode], RESOLVE), resolved_store, lambda: emit(INSPECT_AT, 0, path=1)))
            w.set(final, IMAGE)

        w.if_(w.eq(w[status], DONE), done_out)
    w.if_(w.eq(w[status], FAILED), lambda: w.set(final, FAILED))

    # Every view released (``munmap`` of the whole view: the deallocator contract).
    released = []
    for name, (pointer_type_, extent, _alignment) in buffers.items():
        pointer_name, token_name, memory_name, _element = views[name]
        _result, memory = w.syscall(api.munmap_view(pointer_type_, extent), (proc[pointer_name], proc[token_name], proc[memory_name]), (B64, MEM))
        released.append(memory)
    # The process ends here: ``exit_group`` with the status (a return would trap).
    process = proc.op1(Operation.CALL_FOREIGN, (proc.op1(Operation.INT_TRUNCATE, (w[final],), B32), proc["process"]), PROCESS, entity=api.exit_group)
    proc.ret(proc["fs"], process, *released)
    function = proc.function((FS, PROCESS, *(MEM,) * len(buffers)))
    readers = (decoder_reader, graph_reader, backend_reader, typing_reader, verifier_reader, cfg_reader,
               *((general_reader, writer_reader) if general else ()))
    component_objects = [item for reader in readers for item in reader.objects()
                         if item.kind not in (Kind.MODULE, Kind.PROGRAM_ROOT, Kind.TARGET)]
    objects_ = (*proc.graph.objects.values(), *hash_objects, *semantic_objects, *type_objects, *request_objects, *resolve_objects,
                *component_objects,
                *api.types, *startup.symbols, WRITE_RW)
    return program_store(function, x86_64_linux_exec_target(), objects_), function


def _elf_header_words() -> tuple[tuple[int, ...], tuple[int, int]]:
    """``views_executable``'s 176-byte header as little-endian words, and the two words (``p_filesz``, ``p_memsz``)
    that hold the file size."""
    from xax_linux import _emit_static

    class _Empty:
        code, entry_offset = b"", 0

    header, code_offset, _imports = _emit_static(_Empty())
    words = tuple(int.from_bytes(header[k:k + 8], "little") for k in range(0, len(header), 8))
    sizes = tuple(index for index, word in enumerate(words) if word == len(header))
    assert code_offset == len(header) and sizes == (12, 13), sizes  # the load segment's sizes; nothing else equals 176
    return words, sizes


ELF_HEADER_WORDS, ELF_SIZE_WORDS = _elf_header_words()
ELF_HEADER_SIZE = 8 * len(ELF_HEADER_WORDS)


def _write_declaration():
    from xax_compiler import LINUX_X86_64_SYSCALL_ABI, foreign_function_symbol
    from xax_linux import _LIBRARY, linux_api
    from xax_x86_64 import encode_syscall_name

    api = linux_api()
    return foreign_function_symbol(_LIBRARY, encode_syscall_name(1), (api.b32, api.bytes_rw, api.b64, api.filesystem_effect, api.memory_effect),
                                   (api.b64, api.filesystem_effect, api.memory_effect), abi=LINUX_X86_64_SYSCALL_ABI)


WRITE_RW = _write_declaration()  # ``write`` from a read-write view (the profile narrows no permission for a syscall)


def in_view_extent(view: SemanticObject) -> int:
    from xax_compiler import _heap_view_info

    return _heap_view_info(view)[0]


out_view_extent = in_view_extent


def build_general_driver_program() -> tuple[StoreReader, SemanticObject]:
    """S12e.2 (ADR-276): the general driver's store and entry."""
    return build_driver_program(general=True)


def load_driver_program(general: bool = False) -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader((GENERAL_STORE_PATH if general else STORE_PATH).read_bytes())
    verify_component_store(reader, "compiler-driver-general" if general else "compiler-driver")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_driver_store(general: bool = False) -> bytes:
    reader, _function = build_driver_program(general)
    (GENERAL_STORE_PATH if general else STORE_PATH).write_bytes(reader.data)
    return reader.data


def write_general_driver_store() -> bytes:
    """S12e.2 (ADR-276): the general driver's store."""
    return write_driver_store(general=True)


def target_package(target: SemanticObject) -> bytes:
    """A target-package store: ``target`` as the root object."""
    from xax_compiler import write_store

    return write_store(target.cid, [target])


class NativeDriver:
    """S11 (ADR-267): the driver as a Linux process.  The image (lowered by the XAX backend for
    ``x86_64-linux-views-exec-v1``) is written once as its static ELF64 executable; ``run`` executes it with the three
    paths as its arguments and returns its exit status.  No Python runs inside the process."""

    timeout = None  # seconds per process; None waits

    def __init__(self, image=None) -> None:
        import os
        import tempfile

        from xax_compiler import x86_64_views_exec_target
        from xax_x86_64_views import compile_x86_64_views, views_executable

        if image is None:
            reader, function = load_driver_program()
            image = compile_x86_64_views(reader, function.cid, x86_64_views_exec_target(), backend="xax")
        self.image = image
        self.executable = views_executable(image)
        self._directory = tempfile.TemporaryDirectory(prefix="xax-driver-")
        self.path = Path(self._directory.name) / "xax-driver"
        self.path.write_bytes(self.executable)
        os.chmod(self.path, 0o755)

    def run(self, store_path: str | Path, target_path: str | Path, output_path: str | Path) -> int:
        """The process's exit status (``IMAGE`` .. ``FAILED``); a negative value is the signal that ended it."""
        return self._process(store_path, target_path, output_path)

    def _process(self, *arguments: str | Path) -> int:
        import subprocess

        return subprocess.run([str(self.path), *(str(item) for item in arguments)], check=False, timeout=self.timeout).returncode


class NativeGeneralDriver(NativeDriver):
    """S13a (ADR-281), S13b (ADR-282): the general driver as a Linux process.  Its first argument is the command:
    ``lower`` (a program store, a target package, the output), ``build`` (a build snapshot store, the artifact, its
    provenance), ``verify`` or ``inspect`` (a store, the output), ``resolve`` (a request store, the snapshot store).
    S15c.2 (ADR-300): ``build`` and ``resolve`` take up to ``xax_selfhost_request.INPUTS_LIMIT`` external input files
    after their own arguments."""

    def __init__(self, image=None) -> None:
        if image is None:
            from xax_compiler import x86_64_views_exec_target
            from xax_x86_64_views import compile_x86_64_views

            reader, function = load_driver_program(general=True)
            image = compile_x86_64_views(reader, function.cid, x86_64_views_exec_target(), backend="xax")
        super().__init__(image)

    def run(self, store_path: str | Path, target_path: str | Path, output_path: str | Path) -> int:
        return self._process("lower", store_path, target_path, output_path)

    def build(self, snapshot_path: str | Path, artifact_path: str | Path, provenance_path: str | Path, *inputs: str | Path) -> int:
        """The exit status; on ``IMAGE`` the artifact and the provenance object's envelope are written, on ``REJECTED``
        the diagnostic record is in the artifact's file.  ``inputs``: the external input files (S15c.2)."""
        return self._process("build", snapshot_path, artifact_path, provenance_path, *inputs)

    def verify(self, store_path: str | Path, output_path: str | Path) -> int:
        """S13b: ``IMAGE`` (an empty output) when the store verifies; ``REJECTED`` with the diagnostic record."""
        return self._process("verify", store_path, output_path)

    def inspect(self, store_path: str | Path, output_path: str | Path) -> int:
        """S13b: on ``IMAGE`` the verified store's inspection record (``decode_inspection``)."""
        return self._process("inspect", store_path, output_path)

    def resolve(self, request_path: str | Path, snapshot_path: str | Path, *inputs: str | Path) -> int:
        """S13c: on ``IMAGE`` the snapshot store for the request store's request (``xax_selfhost_resolve``); S15c.2: its
        external input digests are those of ``inputs``."""
        return self._process("resolve", request_path, snapshot_path, *inputs)


def decode_inspection(data: bytes) -> dict:
    """``xaxc inspect``'s JSON object from the record ``inspect`` wrote (little-endian words): the root CID, then per
    object in store order its kind, reference count, CID, and reference CIDs.  It renders words (CID words to hex, a
    kind number to its lowercase name) and decides nothing."""
    words = [int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)]
    position = 0

    def take(count: int):
        nonlocal position
        position += count
        return words[position - count:position]

    def cid() -> str:
        return b"".join(word.to_bytes(8, "big") for word in take(4)).hex()

    root = cid()
    (count,) = take(1)
    objects = []
    for _ in range(count):
        kind, references = take(2)
        objects.append({"cid": cid(), "kind": Kind(kind).name.lower(), "references": [cid() for _ in range(references)]})
    if position != len(words):
        raise ValueError(f"inspection record has {len(words) - position} trailing words")
    return {"root_cid": root, "objects": objects}
