"""Reference edits must rebuild the package and resolved snapshot, not parse them as a request."""
import unittest

from xax_compiler import Kind, verify_store
from xax_construct import construct
from xax_selfhost_edit import REPLACE_REFERENCE, apply_reference, edit_record


def library(value):
    return construct({
        "format": "xax-construct-v1", "platform": "windows-x86_64", "types": {},
        "functions": [{"name": "answer", "params": [], "returns": ["b32"], "blocks": [
            {"params": [], "nodes": [], "end": ["ret", [["b32", value]]]}]}],
        "package": {"name": "edit-package", "entries": {"lib": "answer"}, "release": "lib",
                    "exports": {"Answer": "answer"}}}).reader


class PackagedSnapshotEditTests(unittest.TestCase):
    def test_module_reference_rebuilds_package_request_and_snapshot(self):
        old, desired = library(42), library(43)
        module = next(o for o in old.objects() if o.kind == Kind.MODULE)
        replacement = next(o for o in desired.objects() if o.kind == Kind.MODULE)
        package = next(o for o in old.objects() if o.kind == Kind.PACKAGE)
        old_function = next(o for o in old.objects() if o.kind == Kind.FUNCTION)
        new_function = next(o for o in desired.objects() if o.kind == Kind.FUNCTION)
        existing = {o.cid for o in old.objects()}
        record = edit_record([(REPLACE_REFERENCE, package.cid, module.cid, replacement.cid),
                              (REPLACE_REFERENCE, package.cid, old_function.cid, new_function.cid)],
                             old.root_cid, [o for o in desired.objects() if o.cid not in existing])
        result = apply_reference(old, record)
        verify_store(result)
        self.assertEqual(result.data, desired.data)
        self.assertEqual(old.data, library(42).data)
        with self.assertRaisesRegex(ValueError, "stale root"):
            apply_reference(desired, record)
