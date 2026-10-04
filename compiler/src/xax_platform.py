"""Small explicit platform-library contracts for useful Android/POSIX programs.

These are ordinary typed foreign declarations.  Effect/resource values are proof
values erased by the ABI; no runtime, allocation, retry, or wrapper layer is
introduced by this module.
"""
from dataclasses import dataclass

from xax_compiler import (
    ANDROID_AAPCS64_C_ABI,
    foreign_entry_code_type,
    foreign_entry_pointer_type,
    EffectDomain,
    ForeignAllocatorContract,
    ForeignDeallocatorContract,
    OpaqueKind,
    Permission,
    ResourceFlags,
    SemanticObject,
    bits_type,
    byte_slice_type,
    effect_type,
    foreign_function_symbol,
    memory_effect_type,
    opaque_type,
    pointer_type,
    resource_type,
)


@dataclass(frozen=True)
class PosixAndroidApi:
    b8: SemanticObject
    b32: SemanticObject
    b64: SemanticObject
    byte_ptr_read: SemanticObject
    byte_ptr_rw: SemanticObject
    function_opaque: SemanticObject
    function_ptr: SemanticObject
    byte_slice: SemanticObject
    utf8_string: SemanticObject
    memory_effect: SemanticObject
    filesystem_effect: SemanticObject
    time_effect: SemanticObject
    process_effect: SemanticObject
    thread_effect: SemanticObject
    network_effect: SemanticObject
    heap_resource: SemanticObject
    malloc: SemanticObject
    free: SemanticObject
    open: SemanticObject
    read: SemanticObject
    write: SemanticObject
    close: SemanticObject
    clock_gettime: SemanticObject
    getpid: SemanticObject
    pthread_create: SemanticObject
    pthread_join: SemanticObject
    socket: SemanticObject
    connect: SemanticObject
    send: SemanticObject
    recv: SemanticObject


    def free_heap_view(self, view_type: SemanticObject) -> SemanticObject:
        """Typed ``free`` declaration for a verifier-proven foreign heap view.

        ``HEAP_VIEW`` deliberately replaces the unknown-size heap owner with an
        extent-bearing linear view token.  C's machine ABI still receives only
        the pointer; this declaration lets the verifier consume that typed view
        on the matching ``free`` call without weakening resource typing.
        """
        return foreign_function_symbol(
            b"libc.so", b"free",
            (self.byte_ptr_rw, view_type, self.memory_effect),
            (self.memory_effect,),
            deallocator=ForeignDeallocatorContract(0, 1),
        )

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (
            self.b8, self.b32, self.b64, self.byte_ptr_read, self.byte_ptr_rw,
            self.function_opaque, self.function_ptr, self.byte_slice, self.memory_effect,
            self.filesystem_effect, self.time_effect, self.process_effect,
            self.thread_effect, self.network_effect, self.heap_resource,
        )

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (
            self.malloc, self.free, self.open, self.read, self.write, self.close,
            self.clock_gettime, self.getpid, self.pthread_create, self.pthread_join,
            self.socket, self.connect, self.send, self.recv,
        )


@dataclass(frozen=True)
class AndroidCEntryApi:
    """Bionic calls that receive an XAX function as a C callback (ADR-107).

    ``c_entry`` is the type of ``FUNCTION_ADDRESS`` for such a callback.  On
    AArch64 the address is the function itself; the target must be pure and
    take only 64-bit integers or pointers.
    """

    c_entry_code: SemanticObject
    c_entry: SemanticObject
    # pthread_create(pthread_t*, attr, start_routine, arg); ``attr`` and ``arg``
    # are passed as 64-bit values (0 for default attributes).
    pthread_create: SemanticObject

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (self.c_entry_code, self.c_entry)


def android_c_entry_api(api: "PosixAndroidApi | None" = None) -> AndroidCEntryApi:
    api = api or posix_android_api()
    code = foreign_entry_code_type(ANDROID_AAPCS64_C_ABI)
    entry = foreign_entry_pointer_type(ANDROID_AAPCS64_C_ABI)
    pthread_create = foreign_function_symbol(
        b"libc.so", b"pthread_create",
        (api.byte_ptr_rw, api.b64, entry, api.b64, api.thread_effect, api.memory_effect),
        (api.b32, api.thread_effect, api.memory_effect),
    )
    return AndroidCEntryApi(code, entry, pthread_create)


def posix_android_api() -> PosixAndroidApi:
    b8 = bits_type(8)
    b32 = bits_type(32)
    b64 = bits_type(64)
    byte_ptr_read = pointer_type(b8, Permission.READ, 1, space=2)
    byte_ptr_rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
    function_opaque = opaque_type(OpaqueKind.FUNCTION)
    function_ptr = pointer_type(function_opaque, Permission.READ, 8, space=2)
    byte_slice = byte_slice_type(b64)
    # UTF-8 validity is a library contract over the same zero-copy byte slice;
    # it deliberately does not create a second core string representation.
    utf8_string = byte_slice

    memory = memory_effect_type()
    filesystem = effect_type(EffectDomain.FILESYSTEM, 0)
    time = effect_type(EffectDomain.TIME, 0)
    process = effect_type(EffectDomain.SYSCALL, 0)
    thread = effect_type(EffectDomain.SYSCALL, 1)
    network = effect_type(EffectDomain.NETWORK, 0)
    # This ghost obligation is paired with malloc's pointer and consumed by free.
    # free(NULL) is defined by the C contract, so the obligation is valid even
    # when allocation returns the null pointer.
    heap = resource_type(0x100, 1, flags=ResourceFlags.RELEASABLE, instance=0)

    libc = b"libc.so"
    malloc = foreign_function_symbol(
        libc, b"malloc", (b64, memory), (byte_ptr_rw, heap, memory),
        allocator=ForeignAllocatorContract((0,), 0, 1, 16, False),
    )
    free = foreign_function_symbol(
        libc, b"free", (byte_ptr_rw, heap, memory), (memory,),
        deallocator=ForeignDeallocatorContract(0, 1),
    )

    open_ = foreign_function_symbol(libc, b"open", (byte_ptr_read, b32, b32, filesystem), (b32, filesystem))
    read = foreign_function_symbol(libc, b"read", (b32, byte_ptr_rw, b64, filesystem, memory), (b64, filesystem, memory))
    write = foreign_function_symbol(libc, b"write", (b32, byte_ptr_read, b64, filesystem), (b64, filesystem))
    close = foreign_function_symbol(libc, b"close", (b32, filesystem), (b32, filesystem))

    clock_gettime = foreign_function_symbol(libc, b"clock_gettime", (b32, byte_ptr_rw, time, memory), (b32, time, memory))
    getpid = foreign_function_symbol(libc, b"getpid", (process,), (b32, process))

    pthread_create = foreign_function_symbol(
        libc, b"pthread_create",
        (byte_ptr_rw, byte_ptr_read, function_ptr, byte_ptr_rw, thread, memory),
        (b32, thread, memory),
    )
    pthread_join = foreign_function_symbol(
        libc, b"pthread_join", (b64, byte_ptr_rw, thread, memory), (b32, thread, memory)
    )

    socket = foreign_function_symbol(libc, b"socket", (b32, b32, b32, network), (b32, network))
    connect = foreign_function_symbol(libc, b"connect", (b32, byte_ptr_read, b32, network), (b32, network))
    send = foreign_function_symbol(libc, b"send", (b32, byte_ptr_read, b64, b32, network), (b64, network))
    recv = foreign_function_symbol(libc, b"recv", (b32, byte_ptr_rw, b64, b32, network, memory), (b64, network, memory))

    return PosixAndroidApi(
        b8, b32, b64, byte_ptr_read, byte_ptr_rw, function_opaque, function_ptr, byte_slice,
        utf8_string, memory, filesystem, time, process, thread, network, heap,
        malloc, free, open_, read, write, close, clock_gettime, getpid,
        pthread_create, pthread_join, socket, connect, send, recv,
    )


POSIX_DESCRIPTOR_RESOURCE_KIND = 0x102


@dataclass(frozen=True)
class PosixDescriptorApi:
    """An open file descriptor's ownership as a linear proof value (ADR-153).

    ``descriptor`` is erased by the ABI like every resource.  Whoever hands a
    descriptor to XAX (a platform contract such as ``detachFd``) hands over the
    token with it; ``close`` is the only declaration that consumes it, so the
    verifier rejects a path that leaks the descriptor or closes it twice.
    ``fdatasync`` makes written data durable before the descriptor is closed.
    """

    descriptor: SemanticObject
    close: SemanticObject
    fdatasync: SemanticObject

    @property
    def objects(self) -> tuple[SemanticObject, ...]:
        return (self.descriptor, self.close, self.fdatasync)


def posix_descriptor_api(api: "PosixAndroidApi | None" = None) -> PosixDescriptorApi:
    api = api or posix_android_api()
    descriptor = resource_type(POSIX_DESCRIPTOR_RESOURCE_KIND, 1, flags=ResourceFlags.LINEAR)
    close = foreign_function_symbol(b"libc.so", b"close", (api.b32, descriptor, api.filesystem_effect), (api.b32, api.filesystem_effect))
    fdatasync = foreign_function_symbol(b"libc.so", b"fdatasync", (api.b32, api.filesystem_effect), (api.b32, api.filesystem_effect))
    return PosixDescriptorApi(descriptor, close, fdatasync)


@dataclass(frozen=True)
class Win32Kernel32Api:
    """Bounded kernel32 contracts for hosted x86-64 Windows PE programs.

    Same rules as the POSIX package: exact typed declarations, proof-only
    effect/resource values, no wrapper layer.  ``HANDLE``/``LPOVERLAPPED`` are
    pointer-sized ``b64`` words; caller buffers are borrowed space-1 pointers.
    """
    b8: SemanticObject
    b32: SemanticObject
    b64: SemanticObject
    byte_ptr_read: SemanticObject
    u32_ptr_rw: SemanticObject
    heap_ptr_rw: SemanticObject
    memory_effect: SemanticObject
    filesystem_effect: SemanticObject
    process_effect: SemanticObject
    heap_resource: SemanticObject
    get_std_handle: SemanticObject
    write_file: SemanticObject
    get_process_heap: SemanticObject
    heap_alloc: SemanticObject
    heap_free: SemanticObject
    exit_process: SemanticObject
    virtual_alloc: SemanticObject

    def virtual_free_view(self, view_type: SemanticObject, pointer: SemanticObject) -> SemanticObject:
        """``VirtualFree(view, 0, MEM_RELEASE)`` consuming a proven heap view typed ``pointer``."""
        return foreign_function_symbol(
            b"kernel32.dll", b"VirtualFree",
            (pointer, self.b64, self.b32, view_type, self.memory_effect),
            (self.b32, self.memory_effect),
            abi=b"win64-c", deallocator=ForeignDeallocatorContract(0, 3),
        )

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (
            self.b8, self.b32, self.b64, self.byte_ptr_read, self.u32_ptr_rw, self.heap_ptr_rw,
            self.memory_effect, self.filesystem_effect, self.process_effect, self.heap_resource,
        )

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (
            self.get_std_handle, self.write_file, self.get_process_heap, self.heap_alloc, self.heap_free,
            self.exit_process, self.virtual_alloc,
        )


def win32_kernel32_api() -> Win32Kernel32Api:
    b8, b32, b64 = bits_type(8), bits_type(32), bits_type(64)
    byte_ptr_read = pointer_type(b8, Permission.READ, 1)
    u32_ptr_rw = pointer_type(b32, Permission.READ_WRITE, 4)
    heap_ptr_rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
    memory = memory_effect_type()
    filesystem = effect_type(EffectDomain.FILESYSTEM, 0)
    process = effect_type(EffectDomain.SYSCALL, 0)
    heap = resource_type(0x100, 1, flags=ResourceFlags.RELEASABLE, instance=0)
    k32, abi = b"kernel32.dll", b"win64-c"
    return Win32Kernel32Api(
        b8, b32, b64, byte_ptr_read, u32_ptr_rw, heap_ptr_rw, memory, filesystem, process, heap,
        foreign_function_symbol(k32, b"GetStdHandle", (b32, process), (b64, process), abi=abi),
        foreign_function_symbol(
            k32, b"WriteFile", (b64, byte_ptr_read, b32, u32_ptr_rw, b64, filesystem, memory), (b32, filesystem, memory), abi=abi
        ),
        foreign_function_symbol(k32, b"GetProcessHeap", (process,), (b64, process), abi=abi),
        # HeapAlloc returns MEMORY_ALLOCATION_ALIGNMENT (16) aligned blocks on x64.
        foreign_function_symbol(
            k32, b"HeapAlloc", (b64, b32, b64, memory), (heap_ptr_rw, heap, memory), abi=abi,
            allocator=ForeignAllocatorContract((2,), 0, 1, 16, False),
        ),
        foreign_function_symbol(
            k32, b"HeapFree", (b64, b32, heap_ptr_rw, heap, memory), (b32, memory), abi=abi,
            deallocator=ForeignDeallocatorContract(2, 3),
        ),
        # Process exit is an explicit call: returning from a PE entry does not
        # end the process while loader worker threads are alive.
        foreign_function_symbol(k32, b"ExitProcess", (b32, process), (process,), abi=abi),
        # VirtualAlloc(NULL, size, type, protect): committed pages are always
        # zero-filled and page aligned, independent of the flag values.
        foreign_function_symbol(
            k32, b"VirtualAlloc", (b64, b64, b32, b32, memory), (heap_ptr_rw, heap, memory), abi=abi,
            allocator=ForeignAllocatorContract((1,), 0, 1, 4096, True),
        ),
    )


@dataclass(frozen=True)
class WasiPreview1Api:
    """Bounded ``wasi_snapshot_preview1`` imports (wasm32 linear-memory pointers)."""
    b32: SemanticObject
    u32_ptr_rw: SemanticObject
    memory_effect: SemanticObject
    process_effect: SemanticObject
    args_sizes_get: SemanticObject
    proc_exit: SemanticObject
    u32_ptr_read: SemanticObject
    fd_write: SemanticObject

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (self.b32, self.u32_ptr_rw, self.u32_ptr_read, self.memory_effect, self.process_effect)

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (self.args_sizes_get, self.proc_exit, self.fd_write)


def wasi_preview1_api() -> WasiPreview1Api:
    b32 = bits_type(32)
    u32_ptr_rw = pointer_type(b32, Permission.READ_WRITE, 4)
    memory = memory_effect_type()
    process = effect_type(EffectDomain.SYSCALL, 0)
    module, abi = b"wasi_snapshot_preview1", b"wasm32-import"
    return WasiPreview1Api(
        b32, u32_ptr_rw, memory, process,
        # errno args_sizes_get(argc*, argv_buf_size*): the host writes both words.
        foreign_function_symbol(module, b"args_sizes_get", (u32_ptr_rw, u32_ptr_rw, memory), (b32, memory), abi=abi),
        # proc_exit does not return; exit is explicit program semantics.
        foreign_function_symbol(module, b"proc_exit", (b32, process), (process,), abi=abi),
        pointer_type(b32, Permission.READ, 4),
        # errno fd_write(fd, iovs*, iovs_len, nwritten*): iovec words hold
        # exposed buffer addresses (pointer_address).  The first memory effect
        # orders the iovec/nwritten storage; the second orders the buffer
        # storage those exposed addresses reach, so its lifetime stays explicit.
        foreign_function_symbol(
            module, b"fd_write",
            (b32, pointer_type(b32, Permission.READ, 4), b32, u32_ptr_rw, memory, memory),
            (b32, memory, memory), abi=abi,
        ),
    )
