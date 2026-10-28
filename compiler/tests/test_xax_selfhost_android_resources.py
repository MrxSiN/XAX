"""S15e.6c (ADR-342): the binary manifest and ``resources.arsc`` written by the XAX program equal the bootstrap's.

Seeded manifests (activities with and without the launcher filter, debuggable or not, an application class, receivers
and services in any order, platform declarations with permissions, features and components) and seeded resource tables
(non-ASCII package names and values, shared values); strings past the pools' 15-bit bound make the program decline and
the front doors still raise.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_manifest as M
import xax_resources as R
from xax_selfhost_android_resources import arsc_with_xax, manifest_with_xax

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
WORDS = ("a", "b", "xax", "é", "Zeta", "app", "x𝄞", "service", "receiver", "name")


def _name(rng: random.Random, parts: int = 2) -> str:
    return ".".join(rng.choice(WORDS) + str(rng.randrange(3)) for _ in range(parts))


def _manifest(rng: random.Random):
    launcher = rng.random() < 0.6
    activity = _name(rng, 3) if launcher or rng.random() < 0.5 else ""
    spec = M.AndroidManifestSpec(_name(rng), activity, min_sdk=rng.choice((21, 28)), target_sdk=rng.choice((33, 35)),
                                 version_code=rng.randint(1, 0x7FFFFFFF), launcher=launcher, debuggable=rng.random() < 0.3)
    kw: dict = {}
    if rng.random() < 0.4:
        kw["application"] = M.AndroidManifestApplication(_name(rng, 3))
    kw["receivers"] = tuple(M.AndroidManifestReceiver(_name(rng, 3), rng.random() < 0.5, rng.choice((None, "x.ACTION", _name(rng))))
                            for _ in range(rng.randint(0, 3)))
    kw["services"] = tuple(M.AndroidManifestService(_name(rng, 3), rng.random() < 0.5) for _ in range(rng.randint(0, 3)))
    if rng.random() < 0.5:
        permissions = {_name(rng, 3): M.AndroidUsesPermission(_name(rng, 3), rng.choice((0, 0, 30)), rng.random() < 0.3) for _ in range(rng.randint(0, 3))}
        features = {item.name: item for item in (M.AndroidUsesFeature(_name(rng, 3), rng.random() < 0.5) for _ in range(rng.randint(0, 2)))}
        components = {}
        for _ in range(rng.randint(0, 3)):
            kind = rng.choice(("service", "receiver"))
            types = tuple(rng.sample(sorted(M.FOREGROUND_SERVICE_TYPES), rng.randint(0, 2))) if kind == "service" else ()
            item = M.AndroidDeclaredComponent(kind, _name(rng, 3), rng.random() < 0.5, types, tuple(_name(rng) for _ in range(rng.randint(0, 2))))
            components[item.class_name] = item
        kw["declarations"] = M.AndroidPlatformDeclarations(tuple({item.name: item for item in permissions.values()}.values()),
                                                           tuple(features.values()), tuple(components.values()))
    return spec, kw


@unittest.skipUnless(LINUX_X86_64, "the XAX Android resources program runs natively on Linux x86-64")
class SelfhostAndroidResourcesTests(unittest.TestCase):
    def test_random_manifests(self):
        rng = random.Random(342)
        for trial in range(40):
            spec, kw = _manifest(rng)
            with self.subTest(trial=trial):
                self.assertEqual(manifest_with_xax(spec, required=True, **kw), M._emit_binary_manifest_python(spec, **kw))

    def test_random_resource_tables(self):
        rng = random.Random(3420)
        for trial in range(30):
            names = sorted({f"{rng.choice(('app', 'title', 'z'))}_{rng.randrange(50)}" for _ in range(rng.randint(1, 8))})
            values = ("", "XAX", "é", "x𝄞y", "same", "Ünïcode " * rng.randint(1, 30))
            spec = R.AndroidResourceSpec(rng.choice(("xax.app", "é.app", "a.b𝄞")), tuple(R.AndroidStringResource(name, rng.choice(values)) for name in names))
            with self.subTest(trial=trial):
                self.assertEqual(arsc_with_xax(spec, required=True), R._emit_resources_arsc_python(spec))

    def test_bound_declines(self):
        spec = R.AndroidResourceSpec("xax.app", (R.AndroidStringResource("big", "x" * 0x8000),))
        self.assertIsNone(arsc_with_xax(spec))
        with self.assertRaises(ValueError):
            R.emit_resources_arsc(spec)
        manifest = M.AndroidManifestSpec("xax.app", "xax.app." + "A" * 0x8000)
        self.assertIsNone(manifest_with_xax(manifest))
        with self.assertRaises(ValueError):
            M.emit_binary_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
