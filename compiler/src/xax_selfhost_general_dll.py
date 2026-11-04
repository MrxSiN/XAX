"""Self-hosting step S15e.3b (ADR-320): Windows PE32+ DLLs decided and written by the general x86-64 program.

``xax_build._build_windows_dll`` builds a ``WINDOWS_DLL`` request on the ``x86_64-windows-pe-v1`` profile.  Before it
lowers anything it reads the package's modules in order and, of every reference-free ``TARGET`` member, decodes the
``windows-pe-export-v1`` exports (``WINDOWS-EXPORT-NAME``), the ``windows-pe-forward-v1`` loader forwards
(``WINDOWS-FORWARD-IDENTITY``) and the ``windows-pe-dllmain-v1`` entry; sorts the exports and the forwards; requires
the build entry to be exported (``WINDOWS-DLL-ENTRY-EXPORTED``) and at most one DllMain (``WINDOWS-DLLMAIN-UNIQUE``);
checks DllMain's signature (``WINDOWS-DLLMAIN-SIGNATURE``) and that its call closure, depth first from a stack, makes no
indirect call and no foreign call outside ``kernel32.dll``'s allowlist (``WINDOWS-DLLMAIN-LOADER-LOCK``).  It then
compiles the entry's closure and, after it, each export's and DllMain's (``extra_roots``: each root's new functions by
CID), and ``emit_pe_dll`` requires distinct names (``PE-EXPORT-UNIQUE``) and a NUL-free DLL name
(``PE-EXPORT-DLL-NAME``) before it writes the container with an export directory (``.edata``).

The driver gives the general program the request instead of the entry (``xax_selfhost_request``'s ``B_DLL``): the
program finds the package, the entry and the plan itself (``dll_plan``), checks each further root (``dll_root``),
orders each root's closure (``dll_sort``), and the PE writer (``xax_selfhost_general_image._pe_fn``) adds the export
section (``dll_edata``) after the checks of ``dll_names``.  A carrier the bootstrap cannot decode (a truncated or
over-long identity, a COM declaration on DllMain's path, a name it renders with replacement characters) declines.
"""

from __future__ import annotations

from xax_selfhost_facts import E
from xax_selfhost_views_backend import GLOBALS

# Fixed words after the front end's globals (the general program's arena starts far above them).
DLL_AT = GLOBALS + 64
(D_ON, D_PACKAGE, D_NROOTS, D_ROOTS, D_EXPORTS, D_NEXPORTS, D_FORWARDS, D_NFORWARDS, D_MAIN, D_ROOT) = (DLL_AT + k for k in range(10))
ENTRY_WORDS = 4  # an export: name position, name length, function object, 0; a forward: name position, length, target position, length


# -- packed byte values in a diagnostic record ---------------------------------------------------------------------


def _entry(e: E, table, k, field):
    return e.ld(e.add(e.add(table, e.mul(k, ENTRY_WORDS)), field))


# -- the plan --------------------------------------------------------------------------------------------------------


# -- ``emit_pe_dll``: names, then the export section -----------------------------------------------------------------

def _names(e: E, k, name: str):
    """Entry ``k`` of the merged names (exports first, then forwards): ``name_at``/``name_n``."""
    p = e.p
    e.var(f"{name}_x", e.flag(e.lt(k, e.ld(D_NEXPORTS))))
    e.var(f"{name}_r", e.sel(e.ne(p[f"{name}_x"], 0), e.add(e.ld(D_EXPORTS), e.mul(k, ENTRY_WORDS)),
                             e.add(e.ld(D_FORWARDS), e.mul(e.sub(k, e.ld(D_NEXPORTS)), ENTRY_WORDS))))
    e.var(f"{name}_at", e.ld(p[f"{name}_r"]))
    e.var(f"{name}_n", e.ld(e.add(p[f"{name}_r"], 1)))


