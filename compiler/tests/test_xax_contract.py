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

    def test_description_is_plain_data(self):
        import json

        description = xax_contract.describe()
        self.assertEqual(json.loads(json.dumps(description)), description)
        self.assertEqual(description["contract"], "xax-host-contract-v1")


if __name__ == "__main__":
    unittest.main()
