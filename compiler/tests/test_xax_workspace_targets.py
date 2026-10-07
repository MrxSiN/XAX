"""Platform carrier edits must publish a verified package closure atomically."""
import dataclasses
import io
import zipfile

import pytest

import xax_workspace
from test_xax_android_surface import fixture
from xax_build import build, decode_snapshot
from xax_compiler import Kind, StoreReader, XaxError, android_arm64_shared_target, verify_store, write_store
from xax_android_components import android_surface_activity_semantics, decode_android_surface_activity
from xax_manifest import android_manifest_semantics, decode_android_manifest_semantics
from xax_workspace import ReplaceTarget, RootRef, Transaction, Workspace


def setup():
    reader, _ = fixture()
    workspace = Workspace(reader)
    manifest = next(obj for obj in reader.objects() if obj.kind == Kind.TARGET and _is_manifest(obj))
    return workspace, manifest


def _is_manifest(obj):
    try:
        decode_android_manifest_semantics(obj)
        return True
    except XaxError:
        return False


def transaction(workspace, old, **changes):
    replacement = android_manifest_semantics(dataclasses.replace(decode_android_manifest_semantics(old), **changes))
    handle = workspace.bind_object(old.cid).handle
    return Transaction(RootRef(workspace.generation), (ReplaceTarget(handle, old.cid, replacement),), (handle,))


def apk(reader):
    request = decode_snapshot(reader.get(reader.root_cid), reader.get).request_root
    return build(reader, request).artifact


def test_private_verify_rollback_commit_and_durable_closure(tmp_path):
    workspace, old = setup()
    before = workspace.reader
    edit = transaction(workspace, old, version_code=2)
    candidate = workspace.verify(edit)
    assert candidate.verified and candidate.touched_objects == 5
    assert workspace.root == before.root_cid and workspace.generation == 0
    assert workspace.rollback(candidate.candidate_handle).rolled_back
    result = workspace.commit(edit)
    assert result.committed and result.touched_objects == 5 and result.reused_objects == 6
    assert result.verified_objects == 5 and workspace.generation == 1
    verify_store(workspace.reader)
    left = zipfile.ZipFile(io.BytesIO(apk(before)))
    right = zipfile.ZipFile(io.BytesIO(apk(workspace.reader)))
    assert left.read('classes.dex') == right.read('classes.dex')
    assert left.read('AndroidManifest.xml') != right.read('AndroidManifest.xml')
    unchanged = {obj.cid for obj in before.objects() if obj.kind not in (Kind.MODULE, Kind.PACKAGE, Kind.BUILD) and obj.cid != old.cid}
    assert unchanged <= {obj.cid for obj in workspace.reader.objects()}
    path = tmp_path / 'program.xax'
    workspace.save(path)
    restored = Workspace.load(path)
    assert restored.root == workspace.root and apk(restored.reader) == apk(workspace.reader)


@pytest.mark.parametrize('method', ['verify', 'commit'])
@pytest.mark.parametrize('failure', ['expected', 'raw_root', 'duplicate', 'unknown_handle', 'native', 'activity', 'min_sdk'])
def test_rejections_leave_canonical_store_unchanged(method, failure):
    workspace, old = setup()
    before = workspace.root
    edit = transaction(workspace, old, version_code=2)
    mutation, = edit.mutations
    if failure == 'expected':
        edit = dataclasses.replace(edit, mutations=(dataclasses.replace(mutation, expected=b'\x00' * 32),))
    elif failure == 'raw_root':
        edit = dataclasses.replace(edit, expected_root=before)
    elif failure == 'duplicate':
        edit = dataclasses.replace(edit, mutations=(mutation, mutation))
    elif failure == 'unknown_handle':
        edit = dataclasses.replace(edit, mutations=(dataclasses.replace(mutation, node='E999999.0'),))
    elif failure == 'native':
        edit = dataclasses.replace(edit, mutations=(dataclasses.replace(mutation, value=android_arm64_shared_target()),))
    elif failure == 'activity':
        edit = transaction(workspace, old, activity_class='fixture.surface.Other')
    else:
        edit = transaction(workspace, old, min_sdk=27)
    result = getattr(workspace, method)(edit)
    assert not getattr(result, 'verified' if method == 'verify' else 'committed')
    assert result.diagnostic is not None
    assert workspace.root == before and workspace.generation == 0


@pytest.mark.parametrize('method', ['verify', 'commit'])
def test_stale_and_aba_generation_are_rejected_during_private_verification(monkeypatch, method):
    workspace, old = setup()
    original_root = workspace.root
    outer = transaction(workspace, old, version_code=3)
    original_verify = xax_workspace.verify_object
    triggered = False

    def racing_verify(obj, resolve):
        nonlocal triggered
        if not triggered:
            triggered = True
            inner = transaction(workspace, old, version_code=2)
            assert workspace.commit(inner).committed
            new = inner.mutations[0].value
            assert workspace.commit(transaction(workspace, new, version_code=1)).committed
            assert workspace.root == original_root and workspace.generation == 2
        return original_verify(obj, resolve)

    monkeypatch.setattr(xax_workspace, 'verify_object', racing_verify)
    result = getattr(workspace, method)(outer)
    assert not getattr(result, 'verified' if method == 'verify' else 'committed')
    assert result.diagnostic.code == 'XAX.WORKSPACE.STALE_ROOT'
    assert workspace.root == original_root and workspace.generation == 2
    assert not workspace.rebase(outer).committed


def test_stale_handle_is_not_rebound_to_another_object():
    workspace, old = setup()
    edit = transaction(workspace, old, version_code=2)
    assert workspace.commit(edit).committed
    stale = dataclasses.replace(edit, expected_root=RootRef(workspace.generation))
    result = workspace.commit(stale)
    assert not result.committed and result.diagnostic.code == 'XAX.WORKSPACE.READ_CONFLICT'


def test_machine_target_edit_and_wrong_object_kind_reject():
    for kind in (Kind.FUNCTION, Kind.TARGET):
        workspace, old = setup()
        subject = next(obj for obj in workspace.reader.objects() if obj.kind == kind and obj.cid != old.cid and (kind != Kind.TARGET or obj.cid == android_arm64_shared_target().cid))
        handle = workspace.bind_object(subject.cid).handle
        edit = Transaction(RootRef(0), (ReplaceTarget(handle, subject.cid, old),), (handle,))
        assert not workspace.commit(edit).committed
        assert workspace.generation == 0


def test_object_query_is_bounded_and_unknown_identity_rejects():
    workspace, old = setup()
    for cid, budget in ((old.cid, 1), (b'\x00' * 32, None)):
        with pytest.raises(XaxError):
            workspace.bind_object(cid, byte_budget=budget)


def test_two_carriers_are_replaced_as_one_consistent_candidate():
    workspace, old = setup()
    surface = next(obj for obj in workspace.reader.objects() if obj.kind == Kind.TARGET and obj.cid not in (old.cid, android_arm64_shared_target().cid))
    _, description = decode_android_surface_activity(surface)
    new_surface = android_surface_activity_semantics(class_descriptor='Lfixture/surface/Renamed;', content_description=description)
    manifest_edit = transaction(workspace, old, activity_class='fixture.surface.Renamed')
    handle = workspace.bind_object(surface.cid).handle
    edit = dataclasses.replace(manifest_edit, mutations=(*manifest_edit.mutations, ReplaceTarget(handle, surface.cid, new_surface)), read_set=(*manifest_edit.read_set, handle))
    assert workspace.verify(edit).verified
    result = workspace.commit(edit)
    assert result.committed and len(result.changed_entities) == 2 and result.touched_objects == 6
    assert apk(workspace.reader)


def test_artifact_provenance_is_not_forged_by_ancestor_rebuild():
    workspace, old = setup()
    reader = workspace.reader
    request = decode_snapshot(reader.get(reader.root_cid), reader.get).request_root
    evidence = build(reader, request).provenance
    workspace = Workspace(StoreReader(write_store(evidence.cid, (*reader.objects(), evidence))))
    root = workspace.root
    result = workspace.commit(transaction(workspace, old, version_code=2))
    assert not result.committed and workspace.root == root
    assert result.diagnostic.rule == 'WORKSPACE-BUILD-REBUILD'
