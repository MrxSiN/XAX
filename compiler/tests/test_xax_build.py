from __future__ import annotations

import json
from pathlib import Path
import unittest

from blake3 import blake3

from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from benchmarks.bench_android_arm64 import minimal_native_init_fixture
from benchmarks.bench_android_libxposed_managed import _managed_callbacks
from xax_android import android_activity_method_ui_semantics, android_activity_resource_ui_semantics
from xax_android_components import android_application_semantics, android_broadcast_receiver_semantics, android_service_semantics

from xax_apk import inspect_apk
from xax_apk_signing import (
    RsaSigningCapability,
    encode_private_signing_capability,
    inspect_apk_v2,
)
from xax_manifest import AndroidManifestSpec, android_manifest_semantics, inspect_binary_manifest
from xax_libxposed import (
    LIBXPOSED_MODULE_LOADED_PARAM,
    LIBXPOSED_PACKAGE_READY_PARAM,
    LibxposedManagedEntryDescription,
    LibxposedHookAdapterDescription,
    LibxposedHookArgumentDescription,
    LibxposedHookCombinedDescription,
    LibxposedDeoptimizationDescription,
    LibxposedModuleServicesDescription,
    LibxposedRemotePreferencesDescription,
    LibxposedHookInstallationDescription,
    LibxposedHookResultDescription,
    LibxposedModuleDescription,
    libxposed_hook_adapter_semantics,
    libxposed_hook_argument_semantics,
    libxposed_hook_combined_semantics,
    libxposed_deoptimization_semantics,
    libxposed_module_services_semantics,
    libxposed_remote_preferences_semantics,
    libxposed_hook_installation_semantics,
    libxposed_hook_result_semantics,
    libxposed_managed_entry_semantics,
    libxposed_module_semantics,
    lower_libxposed_managed_entry,
)
from xax_resources import (
    AndroidResourceSpec,
    AndroidStringResource,
    android_resources_semantics,
    inspect_resources_arsc,
)

from xax_jni import (
    JniReferenceKind,
    jni_env_pointer_type,
    jni_reference_type,
    jni_short_native_symbol,
    jni_type_objects,
)

from xax_build import (
    ArtifactKind,
    BuildCache,
    BuildCacheEntry,
    BuildCapability,
    BuildCapabilityKind,
    BuildEffect,
    BuildMode,
    CapabilityGrant,
    DependencyRequirement,
    TypedBinding,
    build,
    build_profile,
    build_request,
    decode_request,
    decode_snapshot,
    package,
    resolve_packages,
    signature,
    snapshot_store,
    trust_policy,
    validate_build_effects,
    verify_fetched_object,
)
from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    Terminator,
    ValueRef,
    XaxError,
    android_arm64_shared_target,
    android_export_symbol,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    wasm32_target,
    x86_64_windows_target,
)


def fixture(*, target=None, dependency=None, profile=None, policy=None, feature_schema=False):
    b1, b32 = bits_type(1), bits_type(32)
    flag, number, answer = constant(b1, 1), constant(b32, 7), constant(b32, 42)
    graph = graph_fragment(
        (Block((), (Node(Operation.CONSTANT, (), (b32,), entity=answer),), Terminator.return_((ValueRef.node_result(0, 0),))),)
    )
    entry = function(graph, (), (b32,))
    module = object_with_refs(Kind.MODULE, (b1, b32, flag, number, answer, entry))
    app = package(
        b"app",
        (module,),
        dependencies=(() if dependency is None else (dependency,)),
        build_entries=((b"image", entry),),
        feature_types=(((b"flag", b1),) if feature_schema else ()),
        configuration_types=(((b"number", b32),) if feature_schema else ()),
    )
    target = target or x86_64_windows_target()
    profile = profile or build_profile()
    policy = policy or trust_policy()
    request = build_request(
        app,
        b"image",
        target,
        profile,
        features=((TypedBinding(b"flag", flag),) if feature_schema else ()),
        configuration=((TypedBinding(b"number", number),) if feature_schema else ()),
        requested_artifacts=(ArtifactKind.NATIVE_IMAGE,),
    )
    objects = (b1, b32, flag, number, answer, graph, entry, module, app, target, profile, policy, request)
    return objects, app, request, profile, policy


def fake_signature(obj, signer=b"test-key"):
    return signature(obj, b"test-blake3", signer, blake3(signer + obj.cid).digest())


def android_signing_capability() -> RsaSigningCapability:
    raw = json.loads((Path(__file__).parent / "fixtures" / "android_v2_test_signer.json").read_text())
    return RsaSigningCapability(
        int(raw["modulus_hex"], 16),
        int(raw["public_exponent"]),
        int(raw["private_exponent_hex"], 16),
        bytes.fromhex(raw["certificate_der_hex"]),
    )


def fake_verifier(algorithm, signer, root, value):
    return algorithm == b"test-blake3" and value == blake3(signer + root).digest()


class PackageBuildTests(unittest.TestCase):
    def test_deterministic_logical_and_exact_resolution(self):
        lib_type = bits_type(64)
        lib_module = object_with_refs(Kind.MODULE, (lib_type,))
        library = package(b"lib", (lib_module,))
        objects, _, request, _, policy = fixture(dependency=DependencyRequirement.logical(b"lib"))
        candidates = (*objects, lib_type, lib_module, library)
        first = resolve_packages(request, candidates, policy, b"resolver-v1")
        second = resolve_packages(request, reversed(candidates), policy, b"resolver-v1")
        self.assertEqual(first.snapshot.cid, second.snapshot.cid)
        self.assertEqual(tuple(item.cid for item in first.packages), tuple(item.cid for item in second.packages))
        reader = snapshot_store(first, candidates)
        verify_store(reader)

        exact_objects, _, exact_request, _, exact_policy = fixture(dependency=DependencyRequirement.exact(library))
        exact = resolve_packages(exact_request, (*exact_objects, lib_type, lib_module, library), exact_policy, b"resolver-v1")
        self.assertIn(library.cid, {item.cid for item in exact.packages})

    def test_resolution_rejects_ambiguity_and_missing_exact_root(self):
        b64, b16 = bits_type(64), bits_type(16)
        first_module, second_module = object_with_refs(Kind.MODULE, (b64,)), object_with_refs(Kind.MODULE, (b16,))
        first, second = package(b"lib", (first_module,)), package(b"lib", (second_module,))
        objects, _, request, _, policy = fixture(dependency=DependencyRequirement.logical(b"lib"))
        with self.assertRaisesRegex(XaxError, "XAX.RESOLVE.AMBIGUOUS"):
            resolve_packages(request, (*objects, b64, b16, first_module, second_module, first, second), policy, b"resolver-v1")

        missing = DependencyRequirement.exact(bytes(range(32)))
        missing_objects, _, missing_request, _, missing_policy = fixture(dependency=missing)
        with self.assertRaisesRegex(XaxError, "XAX.IDENTITY.OBJECT_MISSING"):
            resolve_packages(missing_request, missing_objects, missing_policy, b"resolver-v1")

    def test_typed_features_and_configuration(self):
        objects, _, request, _, policy = fixture(feature_schema=True)
        resolution = resolve_packages(request, objects, policy, b"resolver-v1")
        verify_store(snapshot_store(resolution, objects))

        b1 = next(item for item in objects if item.kind == Kind.TYPE and item.body.endswith(b"\x01"))
        wrong = constant(b1, 0)
        app = next(item for item in objects if item.kind == Kind.PACKAGE)
        target = next(item for item in objects if item.kind == Kind.TARGET)
        profile = next(item for item in objects if item == objects[-3])
        flag = next(item for item in objects if item.kind == Kind.CONSTANT and item.references == (b1.cid,) and item.body.endswith(b"\x01"))
        bad_request = build_request(
            app,
            b"image",
            target,
            profile,
            features=(TypedBinding(b"flag", flag),),
            configuration=(TypedBinding(b"number", wrong),),
        )
        with self.assertRaisesRegex(XaxError, "XAX.BUILD.VALUE_TYPE"):
            resolve_packages(bad_request, (*objects, wrong, bad_request), policy, b"resolver-v1")

    def test_android_unsigned_apk_is_a_generic_build_artifact(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec(
                "xax.generated",
                "xax.generated.XaxActivity",
                min_sdk=28,
                target_sdk=35,
                version_code=1,
                launcher=True,
            )
        )
        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"],
                ui["listener_callback"],
                ui["activity_export"],
                ui["listener_export"],
                ui["ui_semantics"],
                manifest,
            ),
        )
        app = package(b"android-app", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(
            app,
            b"apk",
            target,
            profile,
            requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,),
        )
        source_objects = tuple(ui["reader"].objects())
        objects = (
            *source_objects,
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"],
            manifest, module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-resolver-v1")
        reader = snapshot_store(resolution, objects)
        first = build(reader, request.cid)
        second = build(reader, request.cid)
        self.assertEqual(first, second)
        view = inspect_apk(first.artifact)
        self.assertEqual(
            tuple(item.name for item in view.entries),
            ("AndroidManifest.xml", "classes.dex", "classes2.dex", "lib/arm64-v8a/libxaxapp.so"),
        )
        self.assertEqual(first.artifact, __import__("benchmarks.bench_android_apk", fromlist=["build_fixture"]).build_fixture()[5])

    def test_android_unsigned_apk_accepts_managed_method_ui_carrier(self):
        ui = ui_activity_fixture()
        method_ui = android_activity_method_ui_semantics(
            initial_text_method_name="hookTarget",
            initial_text_method_result="Original",
        )
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], ui["activity_export"],
                ui["listener_export"], method_ui, manifest,
            ),
        )
        app = package(b"android-method-ui-app", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), ui["activity_export"], ui["listener_export"], method_ui,
            manifest, module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-method-ui-resolver-v1")
        reader = snapshot_store(resolution, objects)
        first = build(reader, request.cid)
        second = build(reader, request.cid)
        self.assertEqual(first.artifact, second.artifact)

        import io, zipfile
        from xax_dex import inspect_dex
        with zipfile.ZipFile(io.BytesIO(first.artifact), "r") as archive:
            activity = inspect_dex(archive.read("classes.dex"))
            listener = inspect_dex(archive.read("classes2.dex"))
        self.assertIn("hookTarget", activity.strings)
        self.assertIn("Original", activity.strings)
        self.assertNotIn("placeholder", activity.strings)
        self.assertNotIn("Original", listener.strings)

    def test_android_unsigned_apk_includes_optional_semantic_resources(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        resources = android_resources_semantics(
            AndroidResourceSpec(
                "xax.generated",
                (
                    AndroidStringResource("app_name", "XAX"),
                    AndroidStringResource("clicked", "Clicked"),
                ),
            )
        )
        resource_ui = android_activity_resource_ui_semantics()
        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], ui["activity_export"],
                ui["listener_export"], resource_ui, manifest, resources,
            ),
        )
        app = package(b"android-resources-app", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), ui["activity_export"], ui["listener_export"], resource_ui,
            manifest, resources, module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-resources-resolver-v1")
        reader = snapshot_store(resolution, objects)
        result = build(reader, request.cid)
        import io, zipfile
        from xax_dex import inspect_dex
        with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
            self.assertIn("resources.arsc", archive.namelist())
            resource_view = inspect_resources_arsc(archive.read("resources.arsc"))
            self.assertNotIn("XAX", inspect_dex(archive.read("classes.dex")).strings)
            self.assertNotIn("Clicked", inspect_dex(archive.read("classes2.dex")).strings)
        self.assertEqual(resource_view.package_name, "xax.generated")
        self.assertEqual(tuple((item.name, item.value) for item in resource_view.entries), (("app_name", "XAX"), ("clicked", "Clicked")))

        wrong_resources = android_resources_semantics(
            AndroidResourceSpec("other.package", (AndroidStringResource("app_name", "XAX"),))
        )
        wrong_module = object_with_refs(
            Kind.MODULE,
            (ui["activity_callback"], ui["listener_callback"], ui["activity_export"], ui["listener_export"], resource_ui, manifest, wrong_resources),
        )
        wrong_app = package(b"android-wrong-resource-package", (wrong_module,), build_entries=((b"apk", ui["activity_callback"]),))
        wrong_request = build_request(wrong_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        wrong_objects = (
            *tuple(ui["reader"].objects()), ui["activity_export"], ui["listener_export"], resource_ui,
            manifest, wrong_resources, wrong_module, wrong_app, target, profile, policy, wrong_request,
        )
        wrong_resolution = resolve_packages(wrong_request, wrong_objects, policy, b"android-resources-resolver-v1")
        wrong_reader = snapshot_store(wrong_resolution, wrong_objects)
        with self.assertRaises(XaxError) as caught:
            build(wrong_reader, wrong_request.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-RESOURCE-PACKAGE")


    def test_android_unsigned_apk_synthesizes_broadcast_receiver_component(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        receiver_semantics = android_broadcast_receiver_semantics(
            exported=True,
            action="xax.generated.ACTION_TEST",
        )
        env = jni_env_pointer_type()
        receiver_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxReceiver", b"app:xax.generated")
        context_spec = (JniReferenceKind.BORROWED, b"android.content.Context", b"android.boot")
        intent_spec = (JniReferenceKind.BORROWED, b"android.content.Intent", b"android.boot")
        receiver_ref = jni_reference_type(*receiver_spec[:2], loader_domain=receiver_spec[2])
        context_ref = jni_reference_type(*context_spec[:2], loader_domain=context_spec[2])
        intent_ref = jni_reference_type(*intent_spec[:2], loader_domain=intent_spec[2])
        receiver_graph = graph_fragment(
            (Block((env, receiver_ref, context_ref, intent_ref), (), Terminator.return_(())),)
        )
        receiver_callback = function(receiver_graph, (env, receiver_ref, context_ref, intent_ref), ())
        receiver_symbol = jni_short_native_symbol("Lxax/generated/XaxReceiver;", "xaxOnReceive")
        receiver_export = android_export_symbol(receiver_callback, receiver_symbol)
        receiver_types = jni_type_objects((receiver_spec, context_spec, intent_spec))

        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], receiver_callback,
                ui["activity_export"], ui["listener_export"], receiver_export,
                ui["ui_semantics"], manifest, receiver_semantics,
            ),
        )
        app = package(b"android-receiver-app", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), *receiver_types, receiver_graph, receiver_callback, receiver_export,
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"], manifest, receiver_semantics,
            module, app, target, profile, policy, request,
        )
        # Content-addressed duplicates are allowed in the candidate sequence; snapshot storage canonicalizes by CID.
        resolution = resolve_packages(request, objects, policy, b"android-receiver-resolver-v1")
        reader = snapshot_store(resolution, objects)
        result = build(reader, request.cid)

        import io, zipfile
        from xax_android import inspect_android_elf
        from xax_dex import inspect_dex
        with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
            self.assertEqual(
                tuple(archive.namelist()),
                ("AndroidManifest.xml", "classes.dex", "classes2.dex", "classes3.dex", "lib/arm64-v8a/libxaxapp.so"),
            )
            manifest_view = inspect_binary_manifest(archive.read("AndroidManifest.xml"))
            receiver_elements = [item for item in manifest_view.elements if item.name == "receiver"]
            self.assertEqual(len(receiver_elements), 1)
            attrs = {item.name: item.value for item in receiver_elements[0].attributes}
            self.assertEqual(attrs, {"name": "xax.generated.XaxReceiver", "exported": True})
            receiver_dex = inspect_dex(archive.read("classes3.dex"))
            self.assertEqual(receiver_dex.class_descriptor, "Lxax/generated/XaxReceiver;")
            elf = inspect_android_elf(archive.read("lib/arm64-v8a/libxaxapp.so"))
            self.assertIn(receiver_symbol, elf.exports)

        missing_export_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], receiver_callback,
                ui["activity_export"], ui["listener_export"],
                ui["ui_semantics"], manifest, receiver_semantics,
            ),
        )
        missing_export_app = package(
            b"android-receiver-missing-export",
            (missing_export_module,),
            build_entries=((b"apk", ui["activity_callback"]),),
        )
        missing_request = build_request(
            missing_export_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        missing_objects = (
            *tuple(ui["reader"].objects()), *receiver_types, receiver_graph, receiver_callback,
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"], manifest, receiver_semantics,
            missing_export_module, missing_export_app, target, profile, policy, missing_request,
        )
        missing_resolution = resolve_packages(
            missing_request, missing_objects, policy, b"android-receiver-resolver-v1"
        )
        missing_reader = snapshot_store(missing_resolution, missing_objects)
        with self.assertRaises(XaxError) as caught:
            build(missing_reader, missing_request.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-RECEIVER-EXPORT")

    def test_android_unsigned_apk_synthesizes_application_component(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        application_semantics = android_application_semantics()
        env = jni_env_pointer_type()
        application_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxApplication", b"app:xax.generated")
        application_ref = jni_reference_type(*application_ref_spec[:2], loader_domain=application_ref_spec[2])
        graph = graph_fragment((Block((env, application_ref), (), Terminator.return_(())),))
        callback = function(graph, (env, application_ref), ())
        symbol = jni_short_native_symbol("Lxax/generated/XaxApplication;", "xaxOnCreate")
        export = android_export_symbol(callback, symbol)
        types = jni_type_objects((application_ref_spec,))

        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], callback,
                ui["activity_export"], ui["listener_export"], export,
                ui["ui_semantics"], manifest, application_semantics,
            ),
        )
        app = package(b"android-application-app", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), *types, graph, callback, export,
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"], manifest, application_semantics,
            module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-application-resolver-v1")
        reader = snapshot_store(resolution, objects)
        result = build(reader, request.cid)

        import io, zipfile
        from xax_android import inspect_android_elf
        from xax_dex import inspect_dex
        with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
            manifest_view = inspect_binary_manifest(archive.read("AndroidManifest.xml"))
            app_element = next(item for item in manifest_view.elements if item.name == "application")
            attrs = {item.name: item.value for item in app_element.attributes}
            self.assertEqual(attrs["name"], "xax.generated.XaxApplication")
            app_dex = inspect_dex(archive.read("classes3.dex"))
            self.assertEqual(app_dex.class_descriptor, "Lxax/generated/XaxApplication;")
            elf = inspect_android_elf(archive.read("lib/arm64-v8a/libxaxapp.so"))
            self.assertIn(symbol, elf.exports)

    def test_android_unsigned_apk_synthesizes_unbound_service_component(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        service_semantics = android_service_semantics(exported=False)
        env = jni_env_pointer_type()
        service_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxService", b"app:xax.generated")
        service_ref = jni_reference_type(*service_spec[:2], loader_domain=service_spec[2])
        service_graph = graph_fragment((Block((env, service_ref), (), Terminator.return_(())),))
        create_callback = function(service_graph, (env, service_ref), ())
        destroy_callback = function(service_graph, (env, service_ref), ())
        create_symbol = jni_short_native_symbol("Lxax/generated/XaxService;", "xaxOnCreate")
        destroy_symbol = jni_short_native_symbol("Lxax/generated/XaxService;", "xaxOnDestroy")
        create_export = android_export_symbol(create_callback, create_symbol)
        destroy_export = android_export_symbol(destroy_callback, destroy_symbol)
        service_types = jni_type_objects((service_spec,))

        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], create_callback, destroy_callback,
                ui["activity_export"], ui["listener_export"], create_export, destroy_export,
                ui["ui_semantics"], manifest, service_semantics,
            ),
        )
        app = package(b"android-service-app", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), *service_types, service_graph, create_callback, destroy_callback,
            create_export, destroy_export, ui["activity_export"], ui["listener_export"], ui["ui_semantics"],
            manifest, service_semantics, module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-service-resolver-v1")
        reader = snapshot_store(resolution, objects)
        result = build(reader, request.cid)

        import io, zipfile
        from xax_android import inspect_android_elf
        from xax_dex import inspect_dex
        with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
            self.assertEqual(
                tuple(archive.namelist()),
                ("AndroidManifest.xml", "classes.dex", "classes2.dex", "classes3.dex", "lib/arm64-v8a/libxaxapp.so"),
            )
            manifest_view = inspect_binary_manifest(archive.read("AndroidManifest.xml"))
            service_elements = [item for item in manifest_view.elements if item.name == "service"]
            self.assertEqual(len(service_elements), 1)
            attrs = {item.name: item.value for item in service_elements[0].attributes}
            self.assertEqual(attrs, {"name": "xax.generated.XaxService", "exported": False})
            service_dex = inspect_dex(archive.read("classes3.dex"))
            self.assertEqual(service_dex.class_descriptor, "Lxax/generated/XaxService;")
            elf = inspect_android_elf(archive.read("lib/arm64-v8a/libxaxapp.so"))
            self.assertIn(create_symbol, elf.exports)
            self.assertIn(destroy_symbol, elf.exports)

        missing_export_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], create_callback, destroy_callback,
                ui["activity_export"], ui["listener_export"], create_export,
                ui["ui_semantics"], manifest, service_semantics,
            ),
        )
        missing_app = package(
            b"android-service-missing-export", (missing_export_module,), build_entries=((b"apk", ui["activity_callback"]),)
        )
        missing_request = build_request(
            missing_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        missing_objects = (
            *tuple(ui["reader"].objects()), *service_types, service_graph, create_callback, destroy_callback, create_export,
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"], manifest, service_semantics,
            missing_export_module, missing_app, target, profile, policy, missing_request,
        )
        missing_resolution = resolve_packages(missing_request, missing_objects, policy, b"android-service-resolver-v1")
        missing_reader = snapshot_store(missing_resolution, missing_objects)
        with self.assertRaises(XaxError) as caught:
            build(missing_reader, missing_request.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-SERVICE-EXPORT")

    def test_android_unsigned_apk_packages_modern_native_libxposed_metadata(self):
        # API 102 / Vector: native entries ride on a Java entry, whose
        # onModuleLoaded System.loadLibrary is what triggers native_init.
        with self.assertRaises(ValueError):
            LibxposedModuleDescription(native_entries=("libxaxapp.so",), scopes=("com.example.target",))
        ui = ui_activity_fixture()
        managed = _managed_callbacks()
        native_reader, _, native_init, native_callback, _ = minimal_native_init_fixture()
        native_export = android_export_symbol(native_init, b"native_init")
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        xposed = libxposed_module_semantics(
            LibxposedModuleDescription(
                min_api_version=101,
                target_api_version=102,
                static_scope=True,
                java_entries=("xax.generated.XaxModule",),
                native_entries=("libxaxapp.so",),
                scopes=("com.example.target",),
            )
        )
        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], native_init, native_callback, *managed["callbacks"],
                ui["activity_export"], ui["listener_export"], native_export, *managed["exports"],
                ui["ui_semantics"], manifest, xposed, managed["managed"],
            ),
        )
        app = package(b"android-xposed-native", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), *tuple(native_reader.objects()),
            *managed["types"], *managed["graphs"], *managed["callbacks"], *managed["exports"], managed["managed"],
            ui["activity_export"], ui["listener_export"], native_export, ui["ui_semantics"], manifest, xposed,
            module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-xposed-native-resolver-v1")
        reader = snapshot_store(resolution, objects)
        result = build(reader, request.cid)

        import io, zipfile
        from xax_android import inspect_android_elf
        with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
            names = set(archive.namelist())
            self.assertIn("META-INF/xposed/module.prop", names)
            self.assertIn("META-INF/xposed/java_init.list", names)
            self.assertIn("META-INF/xposed/native_init.list", names)
            self.assertIn("META-INF/xposed/scope.list", names)
            self.assertEqual(archive.read("META-INF/xposed/java_init.list"), b"xax.generated.XaxModule\n")
            self.assertNotIn("assets/xposed_init", names)
            self.assertEqual(
                archive.read("META-INF/xposed/module.prop"),
                b"minApiVersion=101\ntargetApiVersion=102\nstaticScope=true\n",
            )
            self.assertEqual(archive.read("META-INF/xposed/native_init.list"), b"libxaxapp.so\n")
            self.assertEqual(archive.read("META-INF/xposed/scope.list"), b"com.example.target\n")
            elf = inspect_android_elf(archive.read("lib/arm64-v8a/libxaxapp.so"))
            self.assertIn(b"native_init", elf.exports)

        missing_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], *managed["callbacks"],
                ui["activity_export"], ui["listener_export"], *managed["exports"],
                ui["ui_semantics"], manifest, xposed, managed["managed"],
            ),
        )
        missing_app = package(
            b"android-xposed-missing-init", (missing_module,), build_entries=((b"apk", ui["activity_callback"]),)
        )
        missing_request = build_request(
            missing_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        missing_objects = (
            *tuple(ui["reader"].objects()), ui["activity_export"], ui["listener_export"],
            *managed["types"], *managed["graphs"], *managed["callbacks"], *managed["exports"], managed["managed"],
            ui["ui_semantics"], manifest, xposed, missing_module, missing_app, target, profile, policy, missing_request,
        )
        missing_resolution = resolve_packages(
            missing_request, missing_objects, policy, b"android-xposed-native-resolver-v1"
        )
        missing_reader = snapshot_store(missing_resolution, missing_objects)
        with self.assertRaises(XaxError) as caught:
            build(missing_reader, missing_request.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-LIBXPOSED-NATIVE-INIT")

    def test_android_unsigned_apk_synthesizes_managed_libxposed_entry(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        services = libxposed_module_services_semantics(
            LibxposedModuleServicesDescription(
                services=("framework-name", "remote-preferences", "list-remote-files"),
                failure_policy="propagate",
            )
        )
        remote_preferences = libxposed_remote_preferences_semantics(
            LibxposedRemotePreferencesDescription()
        )
        xposed = libxposed_module_semantics(
            LibxposedModuleDescription(
                min_api_version=101, target_api_version=102, static_scope=True,
                java_entries=("xax.generated.XaxModule",), scopes=("com.example.target",),
            )
        )
        dex_spec = lower_libxposed_managed_entry(managed, None, None, services, remote_preferences)
        env = jni_env_pointer_type()
        module_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxModule", b"module:xax.generated")
        loaded_ref_spec = (
            JniReferenceKind.BORROWED,
            b"io.github.libxposed.api.XposedModuleInterface$ModuleLoadedParam",
            b"libxposed:102",
        )
        ready_ref_spec = (
            JniReferenceKind.BORROWED,
            b"io.github.libxposed.api.XposedModuleInterface$PackageReadyParam",
            b"libxposed:102",
        )
        module_ref = jni_reference_type(*module_ref_spec[:2], loader_domain=module_ref_spec[2])
        loaded_ref = jni_reference_type(*loaded_ref_spec[:2], loader_domain=loaded_ref_spec[2])
        ready_ref = jni_reference_type(*ready_ref_spec[:2], loader_domain=ready_ref_spec[2])
        loaded_graph = graph_fragment((Block((env, module_ref, loaded_ref), (), Terminator.return_(())),))
        ready_graph = graph_fragment((Block((env, module_ref, ready_ref), (), Terminator.return_(())),))
        loaded_callback = function(loaded_graph, (env, module_ref, loaded_ref), ())
        ready_callback = function(ready_graph, (env, module_ref, ready_ref), ())
        loaded_symbol = jni_short_native_symbol(dex_spec.class_descriptor, "xaxOnModuleLoaded")
        ready_symbol = jni_short_native_symbol(dex_spec.class_descriptor, "xaxOnPackageReady")
        loaded_export = android_export_symbol(loaded_callback, loaded_symbol)
        ready_export = android_export_symbol(ready_callback, ready_symbol)
        managed_types = jni_type_objects((module_ref_spec, loaded_ref_spec, ready_ref_spec))

        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, services, remote_preferences,
            ),
        )
        app = package(b"android-xposed-managed", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, services, remote_preferences,
            module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-xposed-managed-resolver-v1")
        reader = snapshot_store(resolution, objects)
        result = build(reader, request.cid)

        import io, zipfile
        from xax_android import inspect_android_elf
        from xax_dex import inspect_dex
        with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
            self.assertEqual(archive.read("META-INF/xposed/java_init.list"), b"xax.generated.XaxModule\n")
            self.assertEqual(archive.read("META-INF/xposed/scope.list"), b"com.example.target\n")
            managed_dex = inspect_dex(archive.read("classes3.dex"))
            self.assertEqual(managed_dex.class_descriptor, "Lxax/generated/XaxModule;")
            self.assertEqual(managed_dex.superclass_descriptor, "Lio/github/libxposed/api/XposedModule;")
            self.assertIn(LIBXPOSED_MODULE_LOADED_PARAM, managed_dex.strings)
            self.assertIn(LIBXPOSED_PACKAGE_READY_PARAM, managed_dex.strings)
            self.assertIn("loadLibrary", managed_dex.strings)
            self.assertIn("xaxFrameworkName", managed_dex.strings)
            self.assertIn("xaxRemotePreferences", managed_dex.strings)
            self.assertIn("xaxListRemoteFiles", managed_dex.strings)
            self.assertIn("xaxRemotePreferencesIfSupported", managed_dex.strings)
            self.assertIn("xaxPrefBoolean", managed_dex.strings)
            self.assertIn("xaxPrefLong", managed_dex.strings)
            self.assertNotIn("<clinit>", managed_dex.strings)
            elf = inspect_android_elf(archive.read("lib/arm64-v8a/libxaxapp.so"))
            self.assertIn(loaded_symbol, elf.exports)
            self.assertIn(ready_symbol, elf.exports)
            self.assertEqual(elf.imports, ())
            self.assertEqual(elf.relocation_count, 0)

    def test_android_unsigned_apk_installs_bounded_managed_libxposed_hook(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        hooker = libxposed_hook_adapter_semantics(
            LibxposedHookAdapterDescription(inspected_argument_index=None)
        )
        installation = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(
                target_class_name="android.app.Activity",
                target_method_name="onResume",
                hooker_class_name="xax.generated.XaxHooker",
            )
        )
        deoptimization = libxposed_deoptimization_semantics(
            LibxposedDeoptimizationDescription(
                target_class_name="android.app.Activity",
                target_method_name="onResume",
                result_policy="best-effort",
            )
        )
        xposed = libxposed_module_semantics(
            LibxposedModuleDescription(
                min_api_version=101,
                target_api_version=102,
                static_scope=True,
                java_entries=("xax.generated.XaxModule",),
                scopes=("com.example.target",),
            )
        )
        dex_spec = lower_libxposed_managed_entry(managed, installation)
        env = jni_env_pointer_type()
        module_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxModule", b"module:xax.generated")
        loaded_ref_spec = (
            JniReferenceKind.BORROWED,
            b"io.github.libxposed.api.XposedModuleInterface$ModuleLoadedParam",
            b"libxposed:102",
        )
        ready_ref_spec = (
            JniReferenceKind.BORROWED,
            b"io.github.libxposed.api.XposedModuleInterface$PackageReadyParam",
            b"libxposed:102",
        )
        module_ref = jni_reference_type(*module_ref_spec[:2], loader_domain=module_ref_spec[2])
        loaded_ref = jni_reference_type(*loaded_ref_spec[:2], loader_domain=loaded_ref_spec[2])
        ready_ref = jni_reference_type(*ready_ref_spec[:2], loader_domain=ready_ref_spec[2])
        loaded_graph = graph_fragment((Block((env, module_ref, loaded_ref), (), Terminator.return_(())),))
        ready_graph = graph_fragment((Block((env, module_ref, ready_ref), (), Terminator.return_(())),))
        loaded_callback = function(loaded_graph, (env, module_ref, loaded_ref), ())
        ready_callback = function(ready_graph, (env, module_ref, ready_ref), ())
        loaded_symbol = jni_short_native_symbol(dex_spec.class_descriptor, "xaxOnModuleLoaded")
        ready_symbol = jni_short_native_symbol(dex_spec.class_descriptor, "xaxOnPackageReady")
        loaded_export = android_export_symbol(loaded_callback, loaded_symbol)
        ready_export = android_export_symbol(ready_callback, ready_symbol)
        managed_types = jni_type_objects((module_ref_spec, loaded_ref_spec, ready_ref_spec))

        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, hooker, installation, deoptimization,
            ),
        )
        app = package(b"android-xposed-hook", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, hooker, installation, deoptimization,
            module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-xposed-hook-resolver-v1")
        reader = snapshot_store(resolution, objects)
        result = build(reader, request.cid)

        import io, zipfile
        from xax_dex import inspect_dex
        with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
            names = set(archive.namelist())
            self.assertIn("classes3.dex", names)
            self.assertIn("classes4.dex", names)
            managed_dex = inspect_dex(archive.read("classes3.dex"))
            hooker_dex = inspect_dex(archive.read("classes4.dex"))
            self.assertEqual(managed_dex.class_descriptor, "Lxax/generated/XaxModule;")
            self.assertEqual(hooker_dex.class_descriptor, "Lxax/generated/XaxHooker;")
            for expected in ("getClassLoader", "loadClass", "getDeclaredMethod", "deoptimize", "hook", "setExceptionMode", "PROTECTIVE"):
                self.assertIn(expected, managed_dex.strings)
            self.assertIn("proceed", hooker_dex.strings)
            self.assertNotIn("getArg", hooker_dex.strings)
            self.assertNotIn("getDeclaredMethod", hooker_dex.strings)

        missing_adapter_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, installation,
            ),
        )
        missing_adapter_app = package(
            b"android-xposed-hook-missing-adapter", (missing_adapter_module,),
            build_entries=((b"apk", ui["activity_callback"]),),
        )
        missing_adapter_request = build_request(
            missing_adapter_app, b"apk", target, profile,
            requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,),
        )
        missing_objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, installation,
            missing_adapter_module, missing_adapter_app, target, profile, policy, missing_adapter_request,
        )
        missing_resolution = resolve_packages(
            missing_adapter_request, missing_objects, policy, b"android-xposed-hook-resolver-v1"
        )
        missing_reader = snapshot_store(missing_resolution, missing_objects)
        with self.assertRaises(XaxError) as caught:
            build(missing_reader, missing_adapter_request.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-LIBXPOSED-HOOK-CLOSURE")

        result_installation = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(
                target_class_name="com.example.target.XaxActivity",
                target_method_name="hookTarget",
                hooker_class_name="xax.generated.XaxHooker",
            )
        )
        result_policy = libxposed_hook_result_semantics(
            LibxposedHookResultDescription(
                target_class_name="com.example.target.XaxActivity",
                target_method_name="hookTarget",
                replacement_string="Hooked",
            )
        )
        result_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, hooker, result_installation, result_policy,
            ),
        )
        result_app = package(b"android-xposed-result", (result_module,), build_entries=((b"apk", ui["activity_callback"]),))
        result_request = build_request(
            result_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        result_objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, hooker, result_installation, result_policy,
            result_module, result_app, target, profile, policy, result_request,
        )
        result_resolution = resolve_packages(
            result_request, result_objects, policy, b"android-xposed-result-resolver-v1"
        )
        result_reader = snapshot_store(result_resolution, result_objects)
        result_build = build(result_reader, result_request.cid)
        with zipfile.ZipFile(io.BytesIO(result_build.artifact), "r") as archive:
            replacement_hooker = inspect_dex(archive.read("classes4.dex"))
        self.assertIn("Hooked", replacement_hooker.strings)
        self.assertNotIn("getArg", replacement_hooker.strings)

        mismatched = libxposed_hook_result_semantics(
            LibxposedHookResultDescription(
                target_class_name="com.example.target.Other",
                target_method_name="hookTarget",
                replacement_string="Hooked",
            )
        )
        mismatch_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, hooker, result_installation, mismatched,
            ),
        )
        mismatch_app = package(b"android-xposed-result-mismatch", (mismatch_module,), build_entries=((b"apk", ui["activity_callback"]),))
        mismatch_request = build_request(
            mismatch_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        mismatch_objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, hooker, result_installation, mismatched,
            mismatch_module, mismatch_app, target, profile, policy, mismatch_request,
        )
        mismatch_resolution = resolve_packages(
            mismatch_request, mismatch_objects, policy, b"android-xposed-result-resolver-v1"
        )
        mismatch_reader = snapshot_store(mismatch_resolution, mismatch_objects)
        with self.assertRaises(XaxError) as mismatch_error:
            build(mismatch_reader, mismatch_request.cid)
        self.assertEqual(mismatch_error.exception.diagnostic.rule, "ANDROID-APK-LIBXPOSED-RESULT-TARGET")

        argument_hooker = libxposed_hook_adapter_semantics(
            LibxposedHookAdapterDescription(inspected_argument_index=0)
        )
        argument_installation = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(
                target_class_name="com.example.target.XaxActivity",
                target_method_name="hookTarget",
                hooker_class_name="xax.generated.XaxHooker",
                parameter_type_names=("java.lang.String",),
            )
        )
        argument_policy = libxposed_hook_argument_semantics(
            LibxposedHookArgumentDescription(
                target_class_name="com.example.target.XaxActivity",
                target_method_name="hookTarget",
                replacement_string="HookedArg",
            )
        )
        argument_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, argument_hooker,
                argument_installation, argument_policy,
            ),
        )
        argument_app = package(
            b"android-xposed-argument", (argument_module,), build_entries=((b"apk", ui["activity_callback"]),)
        )
        argument_request = build_request(
            argument_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        argument_objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, argument_hooker,
            argument_installation, argument_policy, argument_module, argument_app,
            target, profile, policy, argument_request,
        )
        argument_resolution = resolve_packages(
            argument_request, argument_objects, policy, b"android-xposed-argument-resolver-v1"
        )
        argument_reader = snapshot_store(argument_resolution, argument_objects)
        argument_build = build(argument_reader, argument_request.cid)
        with zipfile.ZipFile(io.BytesIO(argument_build.artifact), "r") as archive:
            argument_managed = inspect_dex(archive.read("classes3.dex"))
            argument_hooker_dex = inspect_dex(archive.read("classes4.dex"))
        self.assertIn("java.lang.String", argument_managed.strings)
        self.assertIn("HookedArg", argument_hooker_dex.strings)
        self.assertIn("getArg", argument_hooker_dex.strings)
        self.assertIn("[Ljava/lang/Object;", argument_hooker_dex.strings)

        combined_policy = libxposed_hook_combined_semantics(
            LibxposedHookCombinedDescription(
                target_class_name="com.example.target.XaxActivity",
                target_method_name="hookTarget",
                argument_replacement_string="HookedArg",
                result_replacement_string="HookedResult",
            )
        )
        combined_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, argument_hooker,
                argument_installation, combined_policy,
            ),
        )
        combined_app = package(
            b"android-xposed-combined", (combined_module,), build_entries=((b"apk", ui["activity_callback"]),)
        )
        combined_request = build_request(
            combined_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        combined_objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, argument_hooker,
            argument_installation, combined_policy, combined_module, combined_app,
            target, profile, policy, combined_request,
        )
        combined_resolution = resolve_packages(
            combined_request, combined_objects, policy, b"android-xposed-combined-resolver-v1"
        )
        combined_reader = snapshot_store(combined_resolution, combined_objects)
        combined_build = build(combined_reader, combined_request.cid)
        with zipfile.ZipFile(io.BytesIO(combined_build.artifact), "r") as archive:
            combined_hooker_dex = inspect_dex(archive.read("classes4.dex"))
        self.assertIn("HookedArg", combined_hooker_dex.strings)
        self.assertIn("HookedResult", combined_hooker_dex.strings)
        self.assertIn("[Ljava/lang/Object;", combined_hooker_dex.strings)

        wrong_signature_install = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(
                target_class_name="com.example.target.XaxActivity",
                target_method_name="hookTarget",
                hooker_class_name="xax.generated.XaxHooker",
            )
        )
        wrong_signature_module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"], ui["listener_callback"], loaded_callback, ready_callback,
                ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
                ui["ui_semantics"], manifest, xposed, managed, argument_hooker,
                wrong_signature_install, argument_policy,
            ),
        )
        wrong_signature_app = package(
            b"android-xposed-argument-wrong-signature", (wrong_signature_module,),
            build_entries=((b"apk", ui["activity_callback"]),),
        )
        wrong_signature_request = build_request(
            wrong_signature_app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)
        )
        wrong_signature_objects = (
            *tuple(ui["reader"].objects()), *managed_types, loaded_graph, ready_graph, loaded_callback, ready_callback,
            ui["activity_export"], ui["listener_export"], loaded_export, ready_export,
            ui["ui_semantics"], manifest, xposed, managed, argument_hooker,
            wrong_signature_install, argument_policy, wrong_signature_module, wrong_signature_app,
            target, profile, policy, wrong_signature_request,
        )
        wrong_signature_resolution = resolve_packages(
            wrong_signature_request, wrong_signature_objects, policy, b"android-xposed-argument-resolver-v1"
        )
        wrong_signature_reader = snapshot_store(wrong_signature_resolution, wrong_signature_objects)
        with self.assertRaises(XaxError) as wrong_signature_error:
            build(wrong_signature_reader, wrong_signature_request.cid)
        self.assertEqual(
            wrong_signature_error.exception.diagnostic.rule,
            "ANDROID-APK-LIBXPOSED-ARGUMENT-SIGNATURE",
        )

    def test_android_unsigned_apk_rejects_libxposed_java_entry_until_generated_entry_exists(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        )
        xposed = libxposed_module_semantics(
            LibxposedModuleDescription(java_entries=("xax.generated.XaxModule",))
        )
        module = object_with_refs(
            Kind.MODULE,
            (ui["activity_callback"], ui["listener_callback"], ui["activity_export"], ui["listener_export"],
             ui["ui_semantics"], manifest, xposed),
        )
        app = package(b"android-xposed-java-reject", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()), ui["activity_export"], ui["listener_export"], ui["ui_semantics"],
            manifest, xposed, module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-xposed-java-resolver-v1")
        reader = snapshot_store(resolution, objects)
        with self.assertRaises(XaxError) as caught:
            build(reader, request.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-LIBXPOSED-JAVA-ENTRY")

    def test_android_signed_apk_uses_explicit_ephemeral_sign_capability(self):
        ui = ui_activity_fixture()
        manifest = android_manifest_semantics(
            AndroidManifestSpec(
                "xax.generated",
                "xax.generated.XaxActivity",
                min_sdk=28,
                target_sdk=35,
                version_code=1,
                launcher=True,
            )
        )
        signer = android_signing_capability()
        signing_capability = BuildCapability(
            BuildCapabilityKind.SIGN,
            bytes.fromhex(signer.identity_sha256),
        )
        module = object_with_refs(
            Kind.MODULE,
            (
                ui["activity_callback"],
                ui["listener_callback"],
                ui["activity_export"],
                ui["listener_export"],
                ui["ui_semantics"],
                manifest,
            ),
        )
        app = package(
            b"android-app",
            (module,),
            build_entries=((b"apk", ui["activity_callback"]),),
            capabilities=(signing_capability,),
        )
        target = android_arm64_shared_target()
        profile = build_profile(grants=(CapabilityGrant(b"android-app", signing_capability),))
        policy = trust_policy()
        request = build_request(
            app,
            b"apk",
            target,
            profile,
            requested_artifacts=(ArtifactKind.ANDROID_SIGNED_APK,),
        )
        objects = (
            *tuple(ui["reader"].objects()),
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"],
            manifest, module, app, target, profile, policy, request,
        )
        private_transport = encode_private_signing_capability(signer)
        effect = BuildEffect(b"android-app", signing_capability, private_transport)
        undeclared_resolution = resolve_packages(request, objects, policy, b"android-resolver-v1")
        undeclared_reader = snapshot_store(undeclared_resolution, objects)
        with self.assertRaises(XaxError) as undeclared:
            build(undeclared_reader, request.cid, effects=(effect,))
        self.assertEqual(undeclared.exception.diagnostic.rule, "BUILD-SIGNING-MATERIAL-DECLARED")

        signing_inputs = {blake3(private_transport).digest(): private_transport}
        resolution = resolve_packages(request, objects, policy, b"android-resolver-v1", external_inputs=signing_inputs)
        reader = snapshot_store(resolution, objects)

        first = build(reader, request.cid, external_inputs=signing_inputs, effects=(effect,))
        second = build(reader, request.cid, external_inputs=signing_inputs, effects=(effect,))
        self.assertEqual(first, second)
        signed = inspect_apk_v2(first.artifact)
        self.assertTrue(signed.signature_valid)
        self.assertTrue(signed.content_digest_valid)
        self.assertTrue(signed.certificate_key_matches)
        self.assertEqual(signed.certificate_sha256, signer.identity_sha256)
        self.assertNotIn(private_transport, reader.data)
        self.assertNotIn(private_transport, first.provenance.envelope())

        with self.assertRaises(XaxError) as missing:
            build(reader, request.cid, external_inputs=signing_inputs)
        self.assertEqual(missing.exception.diagnostic.rule, "ANDROID-APK-SIGNING-CAPABILITY")

        wrong_scope = BuildCapability(BuildCapabilityKind.SIGN, b"\x00" * 32)
        wrong_app = package(
            b"android-wrong-signer",
            (module,),
            build_entries=((b"apk", ui["activity_callback"]),),
            capabilities=(wrong_scope,),
        )
        wrong_profile = build_profile(grants=(CapabilityGrant(b"android-wrong-signer", wrong_scope),))
        wrong_request = build_request(
            wrong_app, b"apk", target, wrong_profile, requested_artifacts=(ArtifactKind.ANDROID_SIGNED_APK,)
        )
        wrong_objects = (
            *tuple(ui["reader"].objects()),
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"], manifest, module,
            wrong_app, target, wrong_profile, policy, wrong_request,
        )
        wrong_resolution = resolve_packages(
            wrong_request, wrong_objects, policy, b"android-resolver-v1", external_inputs=signing_inputs
        )
        wrong_reader = snapshot_store(wrong_resolution, wrong_objects)
        with self.assertRaises(XaxError) as wrong:
            build(
                wrong_reader,
                wrong_request.cid,
                external_inputs=signing_inputs,
                effects=(BuildEffect(b"android-wrong-signer", wrong_scope, private_transport),),
            )
        self.assertEqual(wrong.exception.diagnostic.rule, "ANDROID-APK-SIGNER-IDENTITY")

    def test_android_unsigned_apk_rejects_missing_semantic_manifest(self):
        ui = ui_activity_fixture()
        module = object_with_refs(
            Kind.MODULE,
            (ui["activity_callback"], ui["listener_callback"], ui["activity_export"], ui["listener_export"], ui["ui_semantics"]),
        )
        app = package(b"android-app", (module,), build_entries=((b"apk", ui["activity_callback"]),))
        target = android_arm64_shared_target()
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
        objects = (
            *tuple(ui["reader"].objects()),
            ui["activity_export"], ui["listener_export"], ui["ui_semantics"],
            module, app, target, profile, policy, request,
        )
        resolution = resolve_packages(request, objects, policy, b"android-resolver-v1")
        reader = snapshot_store(resolution, objects)
        with self.assertRaises(XaxError) as caught:
            build(reader, request.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-SEMANTIC-CARRIERS")

    def test_offline_reproducible_build_external_closure_and_cache(self):
        objects, _, request, _, policy = fixture()
        sdk = b"immutable-sdk"
        external = {blake3(sdk).digest(): sdk}
        resolution = resolve_packages(request, objects, policy, b"resolver-v1", external_inputs=external)
        reader = snapshot_store(resolution, objects)
        first = build(reader, request.cid, external_inputs=external)
        second = build(reader, request.cid, external_inputs=external)
        self.assertEqual(first, second)
        self.assertTrue(first.artifact)

        cache = BuildCache()
        cache.put(first)
        self.assertEqual(cache.get(first.key, reader), first.artifact)
        corrupted = BuildCache({first.key: BuildCacheEntry(first.artifact + b"x", first.provenance)})
        with self.assertRaisesRegex(XaxError, "XAX.CACHE.INTEGRITY"):
            corrupted.get(first.key, reader)
        with self.assertRaisesRegex(XaxError, "XAX.BUILD.INPUT_CLOSURE"):
            build(reader, request.cid)
        with self.assertRaisesRegex(XaxError, "XAX.INTEGRITY.EXTERNAL"):
            build(reader, request.cid, external_inputs={next(iter(external)): b"changed"})
        extra_value = b"undeclared-extra"
        with self.assertRaisesRegex(XaxError, "XAX.BUILD.INPUT_CLOSURE"):
            build(
                reader, request.cid,
                external_inputs={**external, blake3(extra_value).digest(): extra_value},
            )

    def test_reproducible_effect_rejection_and_dependency_isolation(self):
        capabilities = tuple(
            BuildCapability(kind, b"scope")
            for kind in (
                BuildCapabilityKind.NETWORK,
                BuildCapabilityKind.CLOCK,
                BuildCapabilityKind.RANDOM,
                BuildCapabilityKind.SIGN,
                BuildCapabilityKind.INVOKE_TOOL,
            )
        )
        network = capabilities[0]
        lib_type = bits_type(64)
        lib_module = object_with_refs(Kind.MODULE, (lib_type,))
        library = package(b"lib", (lib_module,), capabilities=(network,))
        profile = build_profile(grants=tuple(CapabilityGrant(b"app", item) for item in capabilities))
        objects, app, request, _, policy = fixture(
            dependency=DependencyRequirement.logical(b"lib"),
            profile=profile,
        )
        app_module = next(item for item in objects if item.kind == Kind.MODULE)
        entry = next(item for item in objects if item.kind == Kind.FUNCTION)
        app_with_capability = package(
            b"app",
            (app_module,),
            dependencies=(DependencyRequirement.logical(b"lib"),),
            build_entries=((b"image", entry),),
            capabilities=capabilities,
        )
        target = next(item for item in objects if item.kind == Kind.TARGET)
        request = build_request(app_with_capability, b"image", target, profile)
        candidates = (*objects, app_with_capability, request, lib_type, lib_module, library)
        resolution = resolve_packages(request, candidates, policy, b"resolver-v1")
        reader = snapshot_store(resolution, candidates)
        snapshot_view = decode_snapshot(resolution.snapshot, reader.get)
        request_view = decode_request(request, reader.get)
        for capability in capabilities[:3]:
            with self.assertRaisesRegex(XaxError, "XAX.BUILD.REPRODUCIBLE_INPUT"):
                validate_build_effects(reader, snapshot_view, request_view, (BuildEffect(b"app", capability),))
        with self.assertRaisesRegex(XaxError, "XAX.BUILD.CAPABILITY"):
            validate_build_effects(reader, snapshot_view, request_view, (BuildEffect(b"lib", network),))

        ambient = build_profile(
            mode=BuildMode.AMBIENT,
            grants=tuple(CapabilityGrant(b"app", item) for item in capabilities),
        )
        ambient_request = build_request(app_with_capability, b"image", target, ambient)
        ambient_candidates = (*candidates, ambient, ambient_request)
        ambient_resolution = resolve_packages(ambient_request, ambient_candidates, policy, b"resolver-v1")
        ambient_reader = snapshot_store(ambient_resolution, ambient_candidates)
        validate_build_effects(
            ambient_reader,
            decode_snapshot(ambient_resolution.snapshot, ambient_reader.get),
            decode_request(ambient_request, ambient_reader.get),
            tuple(BuildEffect(b"app", item) for item in capabilities),
        )

    def test_package_and_provenance_signature_hooks(self):
        policy = trust_policy(
            require_package_signatures=True,
            require_provenance_signature=True,
            accepted_algorithms=(b"test-blake3",),
            accepted_signers=(b"test-key",),
        )
        objects, app, request, _, _ = fixture(policy=policy)
        package_signature = fake_signature(app)
        candidates = (*objects, package_signature)
        resolution = resolve_packages(
            request,
            candidates,
            policy,
            b"resolver-v1+test-signature-verifier",
            signatures=(package_signature,),
            signature_verifier=fake_verifier,
        )
        reader = snapshot_store(resolution, candidates)
        result = build(reader, request.cid, signature_verifier=fake_verifier)
        provenance_signature = fake_signature(result.provenance)
        cache = BuildCache()
        cache.put(result, (provenance_signature,))
        self.assertEqual(cache.get(result.key, reader, policy=policy, signature_verifier=fake_verifier), result.artifact)
        with self.assertRaisesRegex(XaxError, "XAX.TRUST.REQUIRED"):
            cache.get(result.key, reader, policy=policy, signature_verifier=lambda *_: False)

    def test_cross_target_cache_separation_and_fetch_integrity(self):
        x86_objects, _, x86_request, _, x86_policy = fixture(target=x86_64_windows_target())
        wasm_objects, _, wasm_request, _, wasm_policy = fixture(target=wasm32_target())
        x86_resolution = resolve_packages(x86_request, x86_objects, x86_policy, b"resolver-v1")
        wasm_resolution = resolve_packages(wasm_request, wasm_objects, wasm_policy, b"resolver-v1")
        x86_result = build(snapshot_store(x86_resolution, x86_objects), x86_request.cid)
        wasm_result = build(snapshot_store(wasm_resolution, wasm_objects), wasm_request.cid)
        self.assertNotEqual(x86_result.key, wasm_result.key)
        self.assertNotEqual(x86_result.artifact, wasm_result.artifact)

        package_object = next(item for item in x86_objects if item.kind == Kind.PACKAGE)
        self.assertEqual(verify_fetched_object(package_object.cid, package_object.envelope()), package_object)
        with self.assertRaisesRegex(XaxError, "XAX.INTEGRITY.FETCH"):
            verify_fetched_object(bytes(32), package_object.envelope())


if __name__ == "__main__":
    unittest.main()
