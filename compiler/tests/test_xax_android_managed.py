"""General Android managed classes (ADR-199): carrier canonicality, DEX forms, JNI signature checks."""
from __future__ import annotations

import io
import struct
import unittest
import zipfile

from xax_android_managed import (
    AndroidManagedClass,
    AndroidManagedMethod,
    android_managed_class_semantics,
    check_export_signature,
    decode_android_managed_class,
    lower_android_managed_class,
)
from xax_compiler import XaxError, bits_type, target
from xax_dex import emit_dex039_bridge, inspect_dex
from xax_graph_builder import GraphBuilder
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type


def _activity(**extra):
    return AndroidManagedClass("Lxax/t/A;", "Landroid/app/Activity;", (), (
        AndroidManagedMethod("onCreate", "(Landroid/os/Bundle;)V", "protected", True),
        AndroidManagedMethod("onKeyDown", "(ILandroid/view/KeyEvent;)Z"),
    ), **extra)


def _method_units(dex: bytes, name: str) -> tuple[int, ...]:
    from benchmarks.bench_android_libxposed_managed import _virtual_method_units

    return _virtual_method_units(dex)[name][1]


class ManagedClassTests(unittest.TestCase):
    def test_carrier_round_trips_and_is_canonical(self):
        carrier = android_managed_class_semantics(_activity())
        self.assertEqual(decode_android_managed_class(carrier), _activity())
        self.assertEqual(carrier.cid, android_managed_class_semantics(_activity()).cid)
        # Method order is canonical: declaring them reversed is the same carrier.
        reversed_methods = AndroidManagedClass("Lxax/t/A;", "Landroid/app/Activity;", (), tuple(reversed(_activity().methods)))
        self.assertEqual(android_managed_class_semantics(reversed_methods).cid, carrier.cid)
        with self.assertRaises(XaxError):
            decode_android_managed_class(target(carrier.body[1:]))  # not the carrier identity

    def test_rejections(self):
        for build in (
            lambda: AndroidManagedMethod("onTouch", "(Landroid/view/View;F)Z"),         # no exact JNI float carrier
            lambda: AndroidManagedMethod("onKeyDown", "(ILandroid/view/KeyEvent;)Z", call_super=True),  # super only for void
            lambda: AndroidManagedMethod("<init>", "()V"),
            lambda: AndroidManagedMethod("run", "()V", "private"),
            lambda: AndroidManagedClass("Lxax/t/A;", "Landroid/app/Activity;", (), (AndroidManagedMethod("a", "()V"), AndroidManagedMethod("a", "(I)V"))),
            lambda: AndroidManagedClass("Lxax/t/A;", "Landroid/app/Activity;", (), ()),
        ):
            with self.assertRaises(ValueError):
                build()

    def test_dex_forms(self):
        cls = AndroidManagedClass("Lxax/t/B;", "Ljava/lang/Object;", ("Landroid/view/SurfaceHolder$Callback;",), (
            AndroidManagedMethod("surfaceCreated", "(Landroid/view/SurfaceHolder;)V"),
            AndroidManagedMethod("surfaceChanged", "(Landroid/view/SurfaceHolder;III)V"),
            AndroidManagedMethod("stamp", "(J)J"),
            AndroidManagedMethod("onKeyDown", "(ILandroid/view/KeyEvent;)Z"),
        ))
        dex = emit_dex039_bridge(lower_android_managed_class(android_managed_class_semantics(cls)))
        inspect_dex(dex)
        # Two registers: compact 35c invoke-direct {v0, v1}; return-void (unchanged pre-ADR-199 form).
        self.assertEqual(_method_units(dex, "surfaceCreated")[0] & 0xFF, 0x70)
        # Five registers use the range form: invoke-direct/range {v0..v4}; return-void.
        units = _method_units(dex, "surfaceChanged")
        self.assertEqual((units[0] & 0xFF, units[0] >> 8, units[2], units[3]), (0x76, 5, 0, 0x0E))
        # Wide: ins = this + long (3), result pair in v0-v1, args from v2.
        units = _method_units(dex, "stamp")
        self.assertEqual((units[0] & 0xFF, units[0] >> 8, units[2], units[3], units[4]), (0x76, 3, 2, 0x0B, 0x10))
        # Boolean result: move-result v0; return v0.
        units = _method_units(dex, "onKeyDown")
        self.assertEqual((units[0] >> 8, units[2], units[3], units[4]), (3, 1, 0x0A, 0x0F))

    def test_super_call_precedes_native(self):
        dex = emit_dex039_bridge(lower_android_managed_class(android_managed_class_semantics(_activity())))
        units = _method_units(dex, "onCreate")
        self.assertEqual([units[0] & 0xFF, units[3] & 0xFF], [0x6F, 0x70])  # invoke-super, then invoke-direct

    def test_export_signature_check(self):
        method = AndroidManagedMethod("onKeyDown", "(ILandroid/view/KeyEvent;)Z")
        env = jni_env_pointer_type()
        this = jni_reference_type(JniReferenceKind.BORROWED, b"xax.t.A", loader_domain=b"app:xax.t")
        event = jni_reference_type(JniReferenceKind.BORROWED, b"android.view.KeyEvent", loader_domain=b"android.boot")

        def function(parameters, results):
            graph = GraphBuilder()
            block = graph.block(*parameters)
            block.ret(*(block.const(item, 0) for item in results))
            fn = graph.function(parameters, results)
            objects = {**graph.objects, fn.cid: fn}
            for item in (*parameters, *results):
                objects[item.cid] = item
            from xax_jni import jni_type_objects
            for item in jni_type_objects(((JniReferenceKind.BORROWED, b"xax.t.A", b"app:xax.t"), (JniReferenceKind.BORROWED, b"android.view.KeyEvent", b"android.boot"))):
                objects[item.cid] = item
            return fn, objects.__getitem__

        good = function((env, this, bits_type(32), event), (bits_type(8),))
        self.assertIsNone(check_export_signature(method, "Lxax/t/A;", *good))
        for parameters, results in (
            ((env, this, bits_type(64), event), (bits_type(8),)),   # long for int
            ((env, this, bits_type(32)), (bits_type(8),)),          # missing KeyEvent
            ((env, this, bits_type(32), this), (bits_type(8),)),    # wrong reference class
            ((env, this, bits_type(32), event), ()),                # boolean result missing
        ):
            with self.subTest(parameters=len(parameters), results=len(results)):
                self.assertIsNotNone(check_export_signature(method, "Lxax/t/A;", *function(parameters, results)))

    def test_fixture_apk_is_managed_only(self):
        from benchmarks.bench_android_managed import build_fixture

        apk = build_fixture()[0].artifact
        with zipfile.ZipFile(io.BytesIO(apk)) as archive:
            self.assertEqual(sorted(archive.namelist()), ["AndroidManifest.xml", "classes.dex", "classes2.dex", "classes3.dex", "lib/arm64-v8a/libxaxapp.so"])
            first = inspect_dex(archive.read("classes.dex"))
        self.assertIn("Lxax/managed/MainActivity;", first.strings)
        self.assertEqual(apk, build_fixture()[0].artifact)


if __name__ == "__main__":
    unittest.main()
