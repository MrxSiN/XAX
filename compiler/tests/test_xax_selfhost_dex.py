"""S15e.6d.1 (ADR-343): the DEX 039 bridge written by the XAX program equals ``xax_dex``'s for the core shapes.

Seeded bridges (native methods, static and private; forwarding overrides in the compact and range forms, with and
without the super call; the deferred library load; interfaces; null returns; constant and echo strings with non-BMP
text; assembled methods with every assembled opcode); the Activity UI, click-text and libxposed shapes are not asked.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_dex as D
from xax_selfhost_dex import dex_with_xax

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
P, I = D.DexProto, D.DexInstruction
TYPES = ("I", "J", "Z", "D", "F", "Ljava/lang/String;", "Landroid/os/Bundle;", "[I", "Lx/é;")


def _proto(rng, *, ret=None):
    return P(ret or rng.choice(("V", *TYPES)), tuple(rng.choice(TYPES) for _ in range(rng.randint(0, 4))))


def _spec(rng):
    natives, forwards = {}, {}
    for k in range(rng.randint(0, 4)):
        proto = _proto(rng)
        private = D.DexNativeMethod(f"xax{k}", proto, D.ACC_PRIVATE | D.ACC_NATIVE)
        natives[(private.name, proto)] = private
        if rng.random() < 0.7:
            call_super = proto.return_type == "V" and rng.random() < 0.5
            forwards[(f"on{k}", proto)] = D.DexForwardingOverride(f"on{k}", proto, private.name, D.ACC_PUBLIC, call_super)
    if rng.random() < 0.3:
        item = D.DexNativeMethod("st", _proto(rng), D.ACC_PUBLIC | D.ACC_STATIC | D.ACC_NATIVE)
        natives[(item.name, item.proto)] = item
    library, override = None, None
    if rng.random() < 0.6:
        library = rng.choice(("xaxapp", "lib𝄞"))
        direct = [item for item in forwards.values() if not item.call_super and item.compact]
        if direct and rng.random() < 0.5:
            override = direct[0].name
    nulls = tuple(D.DexNullReturnOverride(f"nul{k}", P("Ljava/lang/Object;", tuple(rng.choice(("I", "Z", "Lx/A;")) for _ in range(rng.randint(0, 3)))))
                  for k in range(rng.randint(0, 2)))
    constants = tuple(D.DexConstantStringMethod(f"text{k}", rng.choice(("hello", "héllo", "x𝄞y", "Lx/A;", "a" * 300))) for k in range(rng.randint(0, 2)))
    echoes = tuple(D.DexEchoStringMethod(f"echo{k}") for k in range(rng.randint(0, 2)))
    assembled = []
    for k in range(rng.randint(0, 2)):
        ref = D.DexMethodRef(rng.choice(("Lq/T;", "Ljava/lang/String;")), rng.choice(("go", "valueOf")), _proto(rng, ret="V"))
        body = [I("const", (0,), literal=rng.choice((-5, 7, 0x12345678))), I("const-string", (1,), rng.choice(("x", "é"))),
                I("new-instance", (2,), "Lq/T;"), I("check-cast", (2,), "Lq/U;"),
                I(rng.choice(("invoke-static", "invoke-virtual", "invoke-direct", "invoke-interface", "invoke-super")), (1, 0, 2)[:rng.randint(0, 3)], ref),
                I("move-result", (0,)), I("move-result-object", (1,)), I("return-void")]
        assembled.append(D.DexAssembledMethod(f"asm{k}", _proto(rng, ret="V"), 12, tuple(body), rng.choice((D.ACC_PUBLIC, D.ACC_PRIVATE | D.ACC_STATIC))))
    return D.DexBridgeSpec("Lxax/generated/Bridge;", rng.choice(("Landroid/app/Activity;", "Ljava/lang/Object;")), tuple(natives.values()),
                           tuple(forwards.values()), interfaces=tuple(rng.sample(("Lx/I;", "La/J;", "Lx/é;"), rng.randint(0, 2))), native_library=library,
                           null_return_overrides=nulls, native_library_load_override=override, constant_string_methods=constants,
                           echo_string_methods=echoes, assembled_methods=tuple(assembled))


@unittest.skipUnless(LINUX_X86_64, "the XAX DEX bridge program runs natively on Linux x86-64")
class SelfhostDexTests(unittest.TestCase):
    def test_named_bridges(self):
        for spec in (D.activity_bridge_spec(), D.interface_callback_bridge_spec("Lx/Cb;", "Landroid/view/View$OnClickListener;", "onClick",
                                                                                P("V", ("Landroid/view/View;",)))):
            self.assertEqual(dex_with_xax(spec, required=True), D._emit_dex039_bridge_python(spec))

    def test_activity_ui_and_click_text(self):
        """S15e.6d.2 (ADR-344): the Activity button (inline text, a resource ID, a managed method with and without its
        argument) and the click-text listener (inline text, a resource ID)."""
        import dataclasses

        button = D.activity_button_bridge_spec(button_text="Héllo 𝄞")
        specs = [button, D.activity_button_resource_bridge_spec(button_text_resource_id=0x7F010002),
                 D.click_text_listener_bridge_spec(text="Clicked é"), D.click_text_listener_bridge_spec(native_library="xaxapp"),
                 D.click_resource_listener_bridge_spec(text_resource_id=0x7F01FFFF)]
        specs.append(dataclasses.replace(button, activity_ui=D.DexActivityUiSpec(button.activity_ui.listener_class_descriptor, button_text_method_name="label"),
                                         constant_string_methods=(D.DexConstantStringMethod("label", "From XAX"),)))
        specs.append(dataclasses.replace(button, activity_ui=D.DexActivityUiSpec(button.activity_ui.listener_class_descriptor, button_text_method_name="echo",
                                                                                 button_text_method_argument="argument"),
                                         echo_string_methods=(D.DexEchoStringMethod("echo"),)))
        for index, spec in enumerate(specs):
            with self.subTest(spec=index):
                self.assertEqual(dex_with_xax(spec, required=True), D._emit_dex039_bridge_python(spec))

    def test_random_bridges(self):
        rng = random.Random(343)
        for trial in range(40):
            spec = _spec(rng)
            with self.subTest(trial=trial):
                self.assertEqual(dex_with_xax(spec, required=True), D._emit_dex039_bridge_python(spec))


if __name__ == "__main__":
    unittest.main()
