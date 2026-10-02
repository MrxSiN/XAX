"""Small explicit platform-library contracts for useful Android/POSIX programs.

These are ordinary typed foreign declarations.  Effect/resource values are proof
values erased by the ABI; no runtime, allocation, retry, or wrapper layer is
introduced by this module.
"""
from dataclasses import dataclass

from xax_compiler import (
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
