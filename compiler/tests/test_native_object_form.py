"""N0 follow-up (ledger 0012, ADR-375): ``define @name`` / ``object <kind> 0x<body>`` / ``end`` supplies a canonical
object with no references, named ``@name`` for the rest of the batch.  Run with the pinned seed (the production
compiler's own ``xaxc edit``): an entry redefined to call a foreign declaration supplied this way, with the body of the
declaration it called, makes the very same store."""

from __future__ import annotations

import platform
import subprocess
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_selfhost_seed import SEED_PATH
from xax_linux import linux_api


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "the seed runs on Linux x86-64")
class ObjectFormTests(unittest.TestCase):
    def test_supplied_declaration_round_trips(self):
        from test_xax_linux import _status_program

        reader = _status_program(lambda b: b.const(X.bits_type(32), 7))[0]
        declaration = linux_api().exit_group
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            store, selector, view = work / "s.xax", work / "sel", work / "view"
            store.write_bytes(reader.data)
            for n in range(len([o for o in reader.objects() if o.kind == X.Kind.FUNCTION])):
                selector.write_text(f"F{n}")
                self.assertEqual(subprocess.run([SEED_PATH, "edit", store, selector, view]).returncode, 0)
                text = view.read_text()
                if f"entity={declaration.cid.hex()}" in text:
                    break
            else:
                self.fail("no function calls the declaration")
            body = "\n".join(text.splitlines()[2:]).replace(f"entity={declaration.cid.hex()}", "entity=@decl")
            batch = work / "b"
            batch.write_text(f"R {reader.root_cid.hex()}\nF{n}\ndefine @decl\nobject {int(declaration.kind)} 0x{declaration.body.hex()}\nend\n"
                             f"define @f\n{body}\nend\nreplace F{n} @f\n")
            out = work / "out.xax"
            self.assertEqual(subprocess.run([SEED_PATH, "edit", store, batch, out]).returncode, 0)
            self.assertEqual(out.read_bytes(), reader.data)


if __name__ == "__main__":
    unittest.main()
