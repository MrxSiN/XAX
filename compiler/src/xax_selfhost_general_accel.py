"""Self-hosting step S15e.7a (ADR-321): accelerator deployment packets decided and written by the general program.

``xax_build.build`` makes an ``ACCELERATOR_DEPLOYMENT`` for a target of architecture 4 (image format 3) with
``xax_accelerator.compile_accelerator``: the target must declare target operations (``ACCELERATOR-TARGET-PROFILE``);
the entry is one block (``ACCELERATOR-SINGLE-BLOCK``) ending in a return (``ACCELERATOR-RETURN``) with the host
interface ``(bits<32>, bits<32>, effect<device,1>) -> (bits<32>, effect<device,1>)`` (``ACCELERATOR-HOST-INTERFACE``),
whose nodes are all ``target`` operations of that target (``ACCELERATOR-TARGET-OPS-ONLY``) in the deployment sequence
of semantic codes 1..6 (``ACCELERATOR-DEPLOY-SEQUENCE``); then the packet: ``MAGIC``, the format, the target's and the
entry's CIDs, the lane width and group count, the memory spaces, the runtime dependencies, and per node its encoding
opcode, semantic code, scope, spaces and flags.

The general x86-64 program takes this path when the driver gives it such a target (``xax_selfhost_request``'s
``PATH_ACCELERATOR``): ``accelerator`` decides and writes the packet as the image record's container bytes, the way the
ELF file is written, so the driver's ``build`` stores it and names it in the provenance.  A target operation contract
with a runtime dependency (the bootstrap requires the caller to allow it; ``build`` allows none) declines.
"""

from __future__ import annotations


def accelerator_with_xax(reader, function_cid: bytes, target_object, required: bool = False) -> bytes | None:
    """The deployment packet the general program writes for a verified store, or None where it cannot run or declines
    (unless ``required``); it raises the ``XaxError`` the program wrote when it rejects."""
    import xax_native
    from xax_compiler import XaxError, fail
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_general_image import IMAGE_AT
    from xax_selfhost_x86_64_general import general_object_table, native_general

    native = native_general()
    table = None if native is None else general_object_table(reader, function_cid, target_object)

    def collect(read):
        (status,) = read(0, 1)
        if status != 1:
            return None, decode_diagnostic(read)
        assembled, _code, length = read(IMAGE_AT, 3)
        if assembled != 1:
            return None, None
        words = read(IMAGE_AT + 3, (length + 7) // 8)
        return b"".join(word.to_bytes(8, "little") for word in words)[:length], None

    packet, diagnostic = native.run(table[0], collect) if table is not None else (None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    if packet is None:
        if native is not None:
            xax_native.declined("x86-64-general-frontend", 1)
        if required:
            fail("XAX.X86_64.GENERAL_FRONTEND", function_cid.hex(), "X86_64-XAX-GENERAL-FRONTEND", "accepted by the XAX general front end",
                 "unavailable or declined")
    return packet


def accelerator_artifact(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s accelerator deployment: S15e.7a (ADR-321) decided by the XAX general program where it runs and decides
    (``"auto"``; ``"xax"`` requires it), else ``xax_accelerator.compile_accelerator_bound_target``.  With
    ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    from xax_accelerator import compile_accelerator_bound_target
    from xax_compiler import XaxError

    def reference() -> bytes:
        return compile_accelerator_bound_target(reader, function_cid, target_object).artifact_bytes

    if frontend == "python":
        return reference()
    packet = accelerator_with_xax(reader, function_cid, target_object, required=frontend == "xax")
    if packet is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15e.7a: the bootstrap rejects ({error.diagnostic.rule}) a deployment the XAX program wrote") from error
        if packet != expected:
            raise AssertionError("S15e.7a accelerator deployments disagree")
    return packet
