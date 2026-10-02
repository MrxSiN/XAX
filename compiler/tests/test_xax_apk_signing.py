from __future__ import annotations

import io
import json
from pathlib import Path
import unittest
import zipfile

from xax_apk import build_unsigned_apk
from xax_apk_signing import (
    RSA_PKCS1_V1_5_SHA256_ID,
    RsaSigningCapability,
    decode_private_signing_capability,
    encode_private_signing_capability,
    inspect_apk_v2,
    sign_apk_v2,
)
from xax_dex import activity_bridge_spec, emit_dex039_bridge
from xax_manifest import AndroidManifestSpec, emit_binary_manifest


FIXTURE = Path(__file__).parent / "fixtures" / "android_v2_test_signer.json"


def signing_capability() -> RsaSigningCapability:
    raw = json.loads(FIXTURE.read_text())
    return RsaSigningCapability(
        int(raw["modulus_hex"], 16),
        int(raw["public_exponent"]),
        int(raw["private_exponent_hex"], 16),
        bytes.fromhex(raw["certificate_der_hex"]),
    )


def unsigned_fixture() -> bytes:
    manifest = emit_binary_manifest(AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity"))
    dex = emit_dex039_bridge(activity_bridge_spec())
    return build_unsigned_apk(manifest, dex, native_libraries={"libxaxapp.so": b"\x7fELF" + b"XAX" * 257})


class ApkV2SigningTests(unittest.TestCase):
    def test_private_signing_capability_transport_roundtrips(self) -> None:
        capability = signing_capability()
        encoded = encode_private_signing_capability(capability)
        self.assertEqual(decode_private_signing_capability(encoded), capability)
        self.assertNotIn(str(capability.private_exponent), repr(capability))
        with self.assertRaises(ValueError):
            decode_private_signing_capability(encoded + b"x")

    def test_v2_signing_is_deterministic_and_zip_remains_readable(self) -> None:
        unsigned = unsigned_fixture()
        capability = signing_capability()
        first = sign_apk_v2(unsigned, capability)
        second = sign_apk_v2(unsigned, capability)
        self.assertEqual(first, second)
        self.assertGreater(len(first), len(unsigned))

        view = inspect_apk_v2(first)
        self.assertEqual(view.signature_algorithm_id, RSA_PKCS1_V1_5_SHA256_ID)
        self.assertTrue(view.signature_valid)
        self.assertTrue(view.content_digest_valid)
        self.assertTrue(view.certificate_key_matches)
        self.assertEqual(view.certificate_sha256, capability.identity_sha256)

        with zipfile.ZipFile(io.BytesIO(first), "r") as archive:
            self.assertEqual(
                archive.namelist(),
                ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libxaxapp.so"],
            )
            self.assertTrue(archive.read("classes.dex").startswith(b"dex\n039\x00"))

    def test_tampered_content_fails_digest_without_changing_signed_data_signature(self) -> None:
        signed = bytearray(sign_apk_v2(unsigned_fixture(), signing_capability()))
        view = inspect_apk_v2(bytes(signed))
        # Mutate a byte in section 1, which is covered by the content digest but
        # does not alter the v2 signed-data blob/signature itself.
        signed[32] ^= 1
        tampered = inspect_apk_v2(bytes(signed))
        self.assertTrue(tampered.signature_valid)
        self.assertFalse(tampered.content_digest_valid)
        self.assertEqual(tampered.signing_block_offset, view.signing_block_offset)

    def test_tampered_signed_data_invalidates_signature(self) -> None:
        signed = bytearray(sign_apk_v2(unsigned_fixture(), signing_capability()))
        view = inspect_apk_v2(bytes(signed))
        needle = bytes.fromhex(view.content_digest_sha256)
        index = bytes(signed).find(needle, view.signing_block_offset, view.central_directory_offset)
        self.assertGreaterEqual(index, 0)
        signed[index] ^= 1
        tampered = inspect_apk_v2(bytes(signed))
        self.assertFalse(tampered.signature_valid)
        self.assertFalse(tampered.content_digest_valid)

    def test_mismatched_certificate_and_private_key_rejects_before_signing(self) -> None:
        capability = signing_capability()
        with self.assertRaisesRegex(ValueError, "does not match"):
            RsaSigningCapability(
                capability.modulus + 2,
                capability.public_exponent,
                capability.private_exponent,
                capability.certificate_der,
            )

    def test_private_exponent_is_not_exposed_by_repr(self) -> None:
        capability = signing_capability()
        text = repr(capability)
        self.assertNotIn(str(capability.private_exponent), text)
        self.assertIn("certificate_der", text)


if __name__ == "__main__":
    unittest.main()
