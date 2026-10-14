"""S10 (ADR-264, ADR-265): the compiler driver is one XAX program that does its own I/O and owns its memory.

The driver reads a program store and a target-package store from files, decides the container, every object's
CID, and every graph's syntax with the XAX decoders, builds the backend's object table, lowers with the XAX x86-64
backend, and writes the image (or the first rejection's diagnostic record) to a file.  Differential: on every
committed store its output equals ``compile_x86_64_views`` (code bytes, or the exact ``Diagnostic``); mutated
stores reject with the bootstrap's container and envelope diagnostics and the graph decoder's; the driver lowers
its own store to its own image (a component fixed point).  S10e (ADR-266): the driver verifies the store semantically
with the XAX typing, store-verifier, CFG, and facts programs over inputs it builds itself
(``xax_selfhost_semantic``): a store ``verify_store`` rejects never yields an image.
"""

from __future__ import annotations

import glob
import os
import platform
import random
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_selfhost_diagnostics import decode_record

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"


def _entry(reader):
    module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
    return next(reader.get(cid) for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)


def _reference(data: bytes, target) -> tuple[str, object]:
    """``compile_x86_64_views``'s outcome for the store bytes ``data``."""
    from xax_x86_64_views import compile_x86_64_views

    try:
        reader = X.StoreReader(data)
        return "image", compile_x86_64_views(reader, _entry(reader).cid, target, backend="python").code
    except X.XaxError as error:
        return "rejected", error.diagnostic


def _bootstrap_store_outcome(data: bytes):
    """The bootstrap container parser and object decoder (the XAX decoder unloaded): None, or the first diagnostic in
    the order the driver decides (the container, then each object in store order)."""
    saved = X._NATIVE_DECODER, X._DECODER_ATTEMPTED
    X._NATIVE_DECODER, X._DECODER_ATTEMPTED = None, True
    try:
        reader = X.StoreReader(data)
        for cid in reader.object_cids:
            reader.get(cid)
        return None
    except X.XaxError as error:
        return error.diagnostic
    finally:
        X._NATIVE_DECODER, X._DECODER_ATTEMPTED = saved


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class DriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeDriver, load_driver_program, target_package
        from xax_x86_64_views import compile_x86_64_views

        reader, function = load_driver_program()
        cls.driver_reader, cls.driver_function = reader, function
        cls.v2 = X.x86_64_views_syscall_target()
        cls.image = compile_x86_64_views(reader, function.cid, cls.v2, backend="xax")
        cls.driver = NativeDriver(cls.image)
        cls.directory = tempfile.mkdtemp()
        cls.targets = {}
        for name, target in (("v1", X.x86_64_views_target()), ("v2", cls.v2)):
            path = os.path.join(cls.directory, f"{name}.xax")
            Path(path).write_bytes(target_package(target))
            cls.targets[name] = path

    def run_driver(self, data: bytes, target: str = "v1"):
        store = os.path.join(self.directory, "store.xax")
        output = os.path.join(self.directory, "out.bin")
        Path(store).write_bytes(data)
        if os.path.exists(output):
            os.unlink(output)
        status = self.driver.run(store, self.targets[target], output)
        produced = Path(output).read_bytes() if os.path.exists(output) else None
        if status == 0:
            return "image", produced
        if status == 1:
            return "rejected", decode_record([int.from_bytes(produced[k:k + 8], "little") for k in range(0, len(produced), 8)])
        return {2: "declined", 3: "failed"}[status], produced

    def test_the_driver_image_is_the_bootstrap_generators(self):
        from xax_x86_64_views import compile_x86_64_views

        self.assertEqual(self.image, compile_x86_64_views(self.driver_reader, self.driver_function.cid, self.v2, backend="python"))

    def test_every_committed_store(self):
        target = X.x86_64_views_target()
        outcomes = set()
        for path in sorted(glob.glob(str(BOOTSTRAP / "*.xax"))):
            data = Path(path).read_bytes()
            with self.subTest(store=Path(path).name):
                expected = _reference(data, target)
                self.assertEqual(self.run_driver(data), expected)
                outcomes.add(expected[0])
        self.assertEqual(outcomes, {"image", "rejected"})

    def test_the_driver_lowers_itself(self):
        """Component fixed point: the driver image, run natively, lowers the driver store to the driver image."""
        self.assertEqual(self.run_driver(self.driver_reader.data, "v2"), ("image", self.image.code))

    def test_container_and_object_rejections_are_the_bootstraps(self):
        rng = random.Random(10)
        base = (BOOTSTRAP / "xax_riscv64_encoder.xax").read_bytes()
        kinds = set()
        for trial in range(120):
            data = bytearray(base)
            change = trial % 4
            if change == 0:
                data = data[:rng.randrange(len(data))]
            elif change == 1:
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            elif change == 2:
                at = rng.randrange(len(data))
                data[at:at] = bytes((rng.randrange(256),))
            else:
                data[rng.randrange(len(data))] = rng.randrange(256)
            expected = _bootstrap_store_outcome(bytes(data))
            if expected is None:
                continue
            with self.subTest(trial=trial):
                self.assertEqual(self.run_driver(bytes(data)), ("rejected", expected))
                kinds.add(expected.code)
        self.assertGreaterEqual(len(kinds), 4, kinds)

    def test_a_forged_object_cid(self):
        """An envelope whose stored CID is wrong (the container re-digested so only the object check fails)."""
        reader = X.StoreReader((BOOTSTRAP / "xax_blake3_hash.xax").read_bytes())
        victim = reader.object_cids[3]
        offset, _length = reader._index[victim]
        data = bytearray(reader.data)
        cid_at = data.index(victim, offset)
        data[cid_at + 31] ^= 1
        digest_end = len(data) - 32 - 4
        from blake3 import blake3

        data[digest_end:digest_end + 32] = blake3(bytes(data[:digest_end])).digest()
        expected = _bootstrap_store_outcome(bytes(data))
        self.assertIsNotNone(expected)
        self.assertEqual(self.run_driver(bytes(data)), ("rejected", expected))

    def test_graph_syntax_rejections_are_the_graph_decoders(self):
        from xax_compiler import _native_graph_decoder

        reader = X.StoreReader((BOOTSTRAP / "xax_cfg_analysis.xax").read_bytes())
        graph = next(item for item in reader.objects() if item.kind == X.Kind.GRAPH_FRAGMENT)
        decoder = _native_graph_decoder()
        for cut in (1, 2, 7, len(graph.body) // 2):
            broken = X.SemanticObject.create(X.Kind.GRAPH_FRAGMENT, graph.body[:-cut], graph.references)
            objects = [item for item in reader.objects() if item.cid != graph.cid] + [broken]
            data = X.write_store(reader.root_cid, objects)
            status, _words, diagnostic = decoder.decode_with_diagnostic(broken.body, len(broken.references), broken.cid)
            self.assertEqual(status, 1)
            # Graph fragments before it in store order decode cleanly, so its rejection is the first.
            with self.subTest(cut=cut):
                self.assertEqual(self.run_driver(data), ("rejected", diagnostic))

    def test_semantic_rejections(self):
        """Random function stores and their semantic mutations (``test_xax_selfhost_verify``): where ``verify_store``
        accepts, the driver's outcome is ``compile_x86_64_views``'s; where it rejects, the driver writes its
        verification record (``XAX.DRIVER.VERIFY``) and no image."""
        from test_xax_selfhost_verify import MUTATIONS, _store

        rng = random.Random(266)
        rules, accepted = set(), 0
        for trial in range(160):
            mutation = MUTATIONS[trial % len(MUTATIONS)]
            reader = _store(rng, mutation)
            if reader is None:
                continue
            X._PARSED_GRAPHS.clear()
            try:
                X.verify_store(reader)
                verified = True
            except X.XaxError:
                verified = False
            with self.subTest(trial=trial, mutation=mutation):
                outcome = self.run_driver(reader.data)
                if verified:
                    self.assertEqual(outcome, _reference(reader.data, X.x86_64_views_target()))
                    accepted += 1
                elif outcome[0] == "rejected":
                    self.assertEqual(outcome[1].code, "XAX.DRIVER.VERIFY")
                    rules.add(outcome[1].rule)
                else:
                    self.assertEqual(outcome[0], "declined")  # no claim; never an image
        self.assertGreaterEqual(accepted, 40)
        self.assertEqual(rules, {"DRIVER-VERIFY-OBJECT", "DRIVER-VERIFY-STORE"})

    def test_type_and_graph_rejections(self):
        """A constant the typing program rejects (DRIVER-VERIFY-TYPE) and an operation whose operand or result types
        are wrong (DRIVER-VERIFY-GRAPH); ``verify_store`` rejects each."""
        from xax_compiler import Operation, SemanticObject, bits_type, object_with_refs, write_store
        from xax_graph_builder import GraphBuilder

        b8, b32 = bits_type(8), bits_type(32)

        def store(build, parameters, results, extra=()):
            graph = GraphBuilder()
            graph.track(b8, b32)
            entry = graph.block(*parameters)
            entry.ret(build(entry))
            function = graph.function(parameters, results)
            module = object_with_refs(X.Kind.MODULE, [function])
            root = object_with_refs(X.Kind.PROGRAM_ROOT, [module])
            return write_store(root.cid, list({item.cid: item for item in (*graph.objects.values(), *extra, function, module, root)}.values()))

        cases = [(store(lambda e: e.op1(Operation.ADD_WRAP, e.params, b32), (b32, b8), (b32,)), "DRIVER-VERIFY-GRAPH"),
                 (store(lambda e: e.op1(Operation.ADD_WRAP, e.params, b8), (b32, b32), (b8,)), "DRIVER-VERIFY-GRAPH")]
        for body in (b"\x00\x02\x01\xff", b"\x00\x01\x01\x00", b"\x00\x01"):
            bad = SemanticObject.create(X.Kind.CONSTANT, body, [b8.cid])
            build = lambda e, bad=bad: e.op1(Operation.ADD_WRAP, (e.params[0], e.op1(Operation.CONSTANT, (), b8, entity=bad)), b8)
            cases.append((store(build, (b8,), (b8,), (bad, b8)), "DRIVER-VERIFY-TYPE"))
        for data, rule in cases:
            with self.subTest(rule=rule):
                X._PARSED_GRAPHS.clear()
                with self.assertRaises(X.XaxError):
                    X.verify_store(X.StoreReader(data))
                outcome = self.run_driver(data)
                self.assertEqual(outcome[0], "rejected")
                self.assertEqual((outcome[1].code, outcome[1].rule), ("XAX.DRIVER.VERIFY", rule))

    def test_target_profile_rejection(self):
        from xax_selfhost_driver import target_package

        target = X.x86_64_linux_exec_target()
        path = os.path.join(self.directory, "other.xax")
        Path(path).write_bytes(target_package(target))
        self.targets["other"] = path
        data = (BOOTSTRAP / "xax_cfg_analysis.xax").read_bytes()
        self.assertEqual(self.run_driver(data, "other"), _reference(data, target))

    def test_an_unreadable_input_fails(self):
        output = os.path.join(self.directory, "missing-out.bin")
        self.assertEqual(self.driver.run(os.path.join(self.directory, "no-such-store.xax"), self.targets["v1"], output), 3)


if __name__ == "__main__":
    unittest.main()
