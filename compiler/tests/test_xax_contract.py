"""ADR-225: the host contract's names exist and its format identities match the modules that define them."""
from __future__ import annotations

import unittest

import xax_contract


class HostContractTests(unittest.TestCase):
    def test_every_listed_interface_exists(self):
        self.assertEqual(xax_contract.missing(), [])

    def test_format_identities_match_their_sources(self):
        from xax_compiler import LINUX_X86_64_STARTUP_ABI
        from xax_construct import FORMAT
        from xax_linux import LINUX_X86_64_PROCESS_CONTRACT

        formats = xax_contract.FORMATS
        self.assertEqual(formats["construct_carrier"], FORMAT)
        self.assertEqual(formats["linux_process"], LINUX_X86_64_PROCESS_CONTRACT)
        self.assertEqual(formats["linux_startup_abi"].encode(), LINUX_X86_64_STARTUP_ABI)
        from xax_compiler import CHECKED_BYTE_VIEW_WIDTHS

        self.assertEqual(tuple(formats["checked_byte_view_widths"]), CHECKED_BYTE_VIEW_WIDTHS)
        self.assertGreaterEqual(xax_contract.HOST_CONTRACT_MINOR, 2)  # byte-view widening (ADR-231)

    def test_prepare_is_on_the_host_surface(self):
        """ADR-250: ``xax_native.prepare`` joined the surface in minor 3."""
        import xax_native

        self.assertGreaterEqual(xax_contract.HOST_CONTRACT_MINOR, 3)
        self.assertIn("prepare", xax_contract.INTERFACES["xax_native"])
        self.assertTrue(callable(xax_native.prepare))
        self.assertEqual(set(xax_native.PREPARE_COMPONENTS),
                         {"blake3-hash", "store-decoder", "graph-decoder", "cfg", "x86-64-views-backend", "typing", "store-verifier"})

    def test_windows_construct_platform_is_on_the_host_surface(self):
        """ADR-252: the windows-x86_64 carrier platform joined the surface in minor 4."""
        from xax_construct import _PLATFORMS

        self.assertGreaterEqual(xax_contract.HOST_CONTRACT_MINOR, 4)
        self.assertEqual(tuple(xax_contract.FORMATS["construct_platforms"]), _PLATFORMS)

    def test_description_is_plain_data(self):
        import json

        description = xax_contract.describe()
        self.assertEqual(json.loads(json.dumps(description)), description)
        self.assertEqual(description["contract"], "xax-host-contract-v1")


if __name__ == "__main__":
    unittest.main()
