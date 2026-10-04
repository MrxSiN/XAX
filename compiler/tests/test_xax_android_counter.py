"""ADR-111: persistent-counter Activity (state, file I/O, lifecycle in XAX) and assembled DEX methods."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from xax_android_counter import counter_activity_semantics, counter_native, decode_counter_activity
from xax_compiler import Kind, Operation, StoreReader, XaxError, bits_type, object_with_refs, target, verify_store, write_store
from xax_graph_builder import GraphBuilder
from xax_platform import posix_android_api, posix_descriptor_api
from xax_dex import DexAssembledMethod, DexInstruction, DexMethodRef, DexProto, _assemble

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import android_counter_app as app  # noqa: E402
from benchmarks import bench_android_art_verify as art  # noqa: E402
from benchmarks import bench_android_bionic as bionic  # noqa: E402


class CounterSemanticsTests(unittest.TestCase):
    def test_carrier_round_trips(self):
        description = decode_counter_activity(counter_activity_semantics(**app.SEMANTICS))
        self.assertEqual((description.activity_descriptor, description.state_file), ("Lxax/counter/CounterActivity;", "xax.counter"))

    def test_state_file_must_be_one_file_name(self):
        for name in ("../escape", "dir/file", "", ".."):
            with self.assertRaises(ValueError):
                counter_activity_semantics(state_file=name)

    def test_carrier_with_invalid_fields_rejects(self):
        fields = (b"xax.counter", b"xax.counter.A", b"xax.counter.B", b"a/b")
        identity = b"android-counter-activity-v1" + b"".join(bytes((len(item),)) + item for item in fields)
        with self.assertRaises(XaxError) as caught:
            decode_counter_activity(target(identity))
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-COUNTER-FIELDS")


def _closing_store(closes: int) -> StoreReader:
    """``(fd, descriptor, fs) -> fs`` that calls the owning ``close`` ``closes`` times."""
    api = posix_android_api()
    descriptors = posix_descriptor_api(api)
    graph = GraphBuilder()
    block = graph.block(bits_type(32), descriptors.descriptor, api.filesystem_effect)
    fd, owner, fs = block.params
    for _ in range(closes):
        _status, fs = block.op(Operation.CALL_FOREIGN, (fd, owner, fs), (bits_type(32), api.filesystem_effect), entity=descriptors.close)
    block.ret(fs)
    function = graph.function(block.parameter_types, (api.filesystem_effect,))
    module = object_with_refs(Kind.MODULE, [function])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    available = {item.cid: item for item in (*graph.objects.values(), *descriptors.objects, *api.types, function, module, root)}
    reachable, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    return StoreReader(write_store(root.cid, tuple(reachable.values())))


def _reachable(start, objects) -> set[bytes]:
    available = {item.cid: item for item in objects}
    seen, pending = set(), [start.cid]
    while pending:
        cid = pending.pop()
        if cid not in seen and cid in available:
            seen.add(cid)
            pending.extend(available[cid].references)
    return seen


class DescriptorOwnershipTests(unittest.TestCase):
    """ADR-153: the descriptor handed over by ``detachFd`` is closed exactly once."""

    def test_one_close_verifies(self):
        verify_store(_closing_store(1))

    def test_leaked_descriptor_rejects(self):
        with self.assertRaises(XaxError) as caught:
            verify_store(_closing_store(0))
        self.assertEqual(caught.exception.diagnostic.code, "XAX.RESOURCE.DROP")

    def test_double_close_rejects(self):
        with self.assertRaises(XaxError) as caught:
            verify_store(_closing_store(2))
        self.assertEqual(caught.exception.diagnostic.code, "XAX.RESOURCE.DUPLICATE")

    def test_click_syncs_before_closing_and_restore_does_not_sync(self):
        descriptors = posix_descriptor_api()
        native = counter_native(decode_counter_activity(counter_activity_semantics(**app.SEMANTICS)))
        objects = (*native.objects, native.on_create, native.on_click)
        click, create = _reachable(native.on_click, objects), _reachable(native.on_create, objects)
        self.assertTrue({descriptors.close.cid, descriptors.fdatasync.cid, descriptors.descriptor.cid} <= click)
        self.assertIn(descriptors.close.cid, create)
        self.assertNotIn(descriptors.fdatasync.cid, create)
        self.assertNotIn(posix_android_api().close.cid, click | create)


class AssembledDexTests(unittest.TestCase):
    def test_encodings(self):
        proto = DexProto("V", ("J",))
        reference = DexMethodRef("Ljava/lang/Long;", "f", proto)
        method = DexAssembledMethod("m", DexProto("V", ()), 6, (
            DexInstruction("const", (3,), literal=0x38000000),
            DexInstruction("invoke-static", (2, 3), reference),
            DexInstruction("invoke-virtual", (1, 2, 3, 4, 5), reference),
            DexInstruction("move-result-wide", (2,)),
            DexInstruction("return-void"),
        ))
        units = _assemble(method, {}, {}, {("Ljava/lang/Long;", "f", proto): 7})
        self.assertEqual(units, (0x0314, 0x0000, 0x3800, 0x2071, 7, 0x0032, 0x556E, 7, 0x4321, 0x020B, 0x000E))

    def test_invalid_instructions_reject(self):
        reference = DexMethodRef("Ljava/lang/Long;", "f", DexProto("V", ()))
        for build in (
            lambda: DexInstruction("invoke-static", (0, 1, 2, 3, 4, 5), reference),
            lambda: DexInstruction("goto", ()),
            lambda: DexInstruction("const", (0,)),
            lambda: DexInstruction("new-instance", (0,), "not-a-type"),
        ):
            with self.assertRaises(ValueError):
                build()


class CounterApkTests(unittest.TestCase):
    def test_apk_is_deterministic_and_committed(self):
        self.assertEqual(app.build()["signed"], app.APK.read_bytes())

    def test_committed_evidence_matches_the_apk(self):
        committed = json.loads(app.EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(committed["apk_sha256"], hashlib.sha256(app.APK.read_bytes()).hexdigest())
        self.assertTrue(all(committed[key]["passed"] for key in ("official_tools", "art_verify", "native_under_bionic")))
        device = committed["device"]
        self.assertIn(device["label"], ("UNEXECUTED", "EXECUTED"))
        if device["label"] == "EXECUTED":
            # A recorded run is a run of exactly this APK, and says whether it was hardware.
            self.assertEqual(device["apk_sha256"], committed["apk_sha256"])
            self.assertTrue(device["passed"])
            self.assertIn(app.ORACLE_PASSED, device["output"][-1])
            self.assertIn("ok: 4", device["output"])
            self.assertIsInstance(device["hardware"], bool)

    def test_twin_evidence_compares_this_apk_with_the_same_behavior(self):
        from benchmarks import bench_android_counter_twin as twin

        committed = json.loads(twin.EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(committed["xax"]["apk_sha256"], hashlib.sha256(app.APK.read_bytes()).hexdigest())
        self.assertTrue(committed["behavior_match"])
        self.assertEqual(set(committed["xax"]["native_function_bytes"]), set(committed["java_ndk"]["native_function_bytes"]))
        device = committed["device"]
        # Start-up time and memory count only from hardware (XAX_SPEC.md section 21.2).
        self.assertTrue(device["label"] != "MEASURED" or device["hardware"] is True)

    @unittest.skipUnless(bionic.QEMU and (bionic.ROOT / "system/bin/linker64").exists() and bionic.JNI_H.exists(), "requires the NDK, qemu-aarch64, and an Android bionic root")
    def test_native_state_survives_restart_under_bionic(self):
        self.assertEqual(app.run_native(app.APK), app.EXPECTED_NATIVE)

    @unittest.skipUnless(art.available(), "requires qemu-aarch64 and the Android root from make_android_root.py")
    def test_art_verifies_both_classes(self):
        import shutil

        art.WORK.mkdir(parents=True, exist_ok=True)
        copy = art.WORK / app.APK.name
        shutil.copy(app.APK, copy)
        self.assertEqual(set(art.verify(copy).values()), {"Verified"})


if __name__ == "__main__":
    unittest.main()
