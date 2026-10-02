"""Target-neutral derived artifact provenance records for XAX bootstrap backends.

These records are compiler-service metadata only. They are not canonical XAX
semantics and must never be used to infer or redefine source meaning.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Protocol


# Opaque binary version identities. They are intentionally literal bytes rather
# than hashes of human-readable names/source text. Any output-affecting compiler
# or lowering change must explicitly bump the corresponding identity.
BOOTSTRAP_COMPILER_IDENTITY_V1 = bytes.fromhex(
    "13dbd0cf3458d70b1e2f817928fa7248dabd7c6dade5ca52624ace6d6c296c78"
)
X86_64_LOWERING_IDENTITY_V1 = bytes.fromhex(
    "d071ac136d8b85c8e3f993804c655b90e3a6ef583e6c472328ce5b28ec51c45c"
)
WASM_LOWERING_IDENTITY_V1 = bytes.fromhex(
    "546ca644b02be7c240931ee7ed46e236ac02b10047506044e82eed530836821b"
)
AARCH64_LOWERING_IDENTITY_V1 = bytes.fromhex(
    "6b4ba19b0a735126006a902a7a030c98c2478dfe21df55bdc5028ea28982f9a9"
)
ACCELERATOR_LOWERING_IDENTITY_V1 = bytes.fromhex(
    "9111f6468ab580637441677af8e06d64046b022cc1b50e4ed67e42501393c510"
)
ANDROID_UNSIGNED_APK_LOWERING_IDENTITY_V1 = bytes.fromhex(
    "8a1ce792e3284d5b891a956fe026cd91431771942065d969837e744c7e9acb22"
)
ANDROID_SIGNED_APK_LOWERING_IDENTITY_V1 = bytes.fromhex(
    "9b56f1305305788260f8bde6bfe0da2c348ca05f48acc310ac9b1ed90c65c97f"
)


def lowering_identity(architecture: int, image_format: int) -> bytes:
    """Return the explicit bootstrap lowering identity for a supported target path."""

    try:
        return {
            (1, 1): X86_64_LOWERING_IDENTITY_V1,
            (2, 2): WASM_LOWERING_IDENTITY_V1,
            (3, 1): AARCH64_LOWERING_IDENTITY_V1,
            (4, 3): ACCELERATOR_LOWERING_IDENTITY_V1,
        }[(architecture, image_format)]
    except KeyError as error:
        raise ValueError("unsupported bootstrap lowering identity") from error


@dataclass(frozen=True)
class ArtifactSemanticRange:
    """Exact half-open artifact byte range retained during lowering/emission."""

    function_cid: bytes
    block_index: int | None
    node_index: int | None
    start: int
    end: int

    def __post_init__(self) -> None:
        if len(self.function_cid) != 32:
            raise ValueError("artifact semantic range function CID must be 32 bytes")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("artifact semantic range must be a non-empty half-open range")
        if (self.block_index is None) != (self.node_index is None):
            raise ValueError("block/node indices must either both be present or both be absent")
        if self.block_index is not None and (self.block_index < 0 or self.node_index < 0):
            raise ValueError("block/node indices must be non-negative")


@dataclass(frozen=True)
class ArtifactProvenanceBinding:
    """Exact dependency attribution for one emitted artifact.

    This binding is derived tooling state. ``identity`` commits to every field
    below, including retained ranges, but does not become canonical XAX source.
    """

    semantic_root: bytes
    target_configuration_cid: bytes
    compiler_identity: bytes
    lowering_identity: bytes
    artifact_digest: bytes
    semantic_ranges: tuple[ArtifactSemanticRange, ...]
    identity: bytes

    def __post_init__(self) -> None:
        for name, value in (
            ("semantic root", self.semantic_root),
            ("target/configuration CID", self.target_configuration_cid),
            ("compiler identity", self.compiler_identity),
            ("lowering identity", self.lowering_identity),
            ("artifact digest", self.artifact_digest),
            ("binding identity", self.identity),
        ):
            if len(value) != 32:
                raise ValueError(f"artifact {name} must be 32 bytes")
        if self.identity != self._identity_bytes(
            self.semantic_root,
            self.target_configuration_cid,
            self.compiler_identity,
            self.lowering_identity,
            self.artifact_digest,
            self.semantic_ranges,
        ):
            raise ValueError("artifact provenance binding identity mismatch")

    @classmethod
    def bind(
        cls,
        semantic_root: bytes,
        target_configuration_cid: bytes,
        compiler_identity: bytes,
        lowering_identity: bytes,
        artifact_bytes: bytes,
        semantic_ranges: tuple[ArtifactSemanticRange, ...],
    ) -> "ArtifactProvenanceBinding":
        artifact_digest = hashlib.sha256(artifact_bytes).digest()
        identity = cls._identity_bytes(
            semantic_root,
            target_configuration_cid,
            compiler_identity,
            lowering_identity,
            artifact_digest,
            semantic_ranges,
        )
        return cls(
            semantic_root,
            target_configuration_cid,
            compiler_identity,
            lowering_identity,
            artifact_digest,
            semantic_ranges,
            identity,
        )

    @staticmethod
    def _identity_bytes(
        semantic_root: bytes,
        target_configuration_cid: bytes,
        compiler_identity: bytes,
        lowering_identity: bytes,
        artifact_digest: bytes,
        semantic_ranges: tuple[ArtifactSemanticRange, ...],
    ) -> bytes:
        for value in (
            semantic_root,
            target_configuration_cid,
            compiler_identity,
            lowering_identity,
            artifact_digest,
        ):
            if len(value) != 32:
                raise ValueError("artifact provenance dependency identities must be 32 bytes")
        payload = bytearray((1,))
        payload.extend(semantic_root)
        payload.extend(target_configuration_cid)
        payload.extend(compiler_identity)
        payload.extend(lowering_identity)
        payload.extend(artifact_digest)
        payload.extend(struct.pack("<Q", len(semantic_ranges)))
        sentinel = (1 << 64) - 1
        for item in semantic_ranges:
            payload.extend(item.function_cid)
            payload.extend(struct.pack("<Q", sentinel if item.block_index is None else item.block_index))
            payload.extend(struct.pack("<Q", sentinel if item.node_index is None else item.node_index))
            payload.extend(struct.pack("<Q", item.start))
            payload.extend(struct.pack("<Q", item.end))
        return hashlib.sha256(payload).digest()

    def matches(
        self,
        semantic_root: bytes,
        target_configuration_cid: bytes,
        compiler_identity: bytes,
        lowering_identity: bytes,
        artifact_bytes: bytes,
        semantic_ranges: tuple[ArtifactSemanticRange, ...],
    ) -> bool:
        """Return whether all recorded attribution dependencies are still exact."""

        return self == ArtifactProvenanceBinding.bind(
            semantic_root,
            target_configuration_cid,
            compiler_identity,
            lowering_identity,
            artifact_bytes,
            semantic_ranges,
        )


class MappableArtifact(Protocol):
    """Minimal target-neutral interface consumed by workspace mapping queries."""

    @property
    def artifact_bytes(self) -> bytes: ...

    entry_offset: int
    parameter_widths: tuple[int, ...]
    return_widths: tuple[int, ...]
    target_cid: bytes
    semantic_ranges: tuple[ArtifactSemanticRange, ...]
