"""S15b.3 (ADR-292): ``_parse_graph``'s outcome, as the typing program decides and renders it, against the host's.

Run as a pytest plugin::

    PYTHONPATH=src:tests:migration python -m pytest -s -p s15_graph tests/...

For every graph the host parses whose uses are valid and whose typing run accepted, the typing program's outcome
(``xax_selfhost_render_graph``) must be the host's: accepted when the parse returns, the same diagnostic when it raises;
a decline makes no claim.  Differences print a ``GRAPH-DIFF`` line; the run ends with ``S15-GRAPH {...}``.
"""

from __future__ import annotations

import sys

STATS = {"accept": 0, "exact": 0, "decline_accepted": 0, "decline_rejected": 0, "diff": 0, "skipped": 0}
RULES: dict = {}
DECLINED: dict = {}


def pytest_configure(config):  # noqa: ARG001 - pytest hook
    install()


def install():
    import xax_compiler as X
    import xax_selfhost_cfg as CF
    import xax_selfhost_render_graph as RG
    import xax_selfhost_typing as T

    frames: list = []
    check = T.NativeTyping.check

    def checked(self, words, count):
        status, verdicts = check(self, words, count)
        if frames and frames[-1]["typing"] is None:
            out = self._out
            frames[-1]["typing"] = (status, list(out[RG.OUTCOME_AT:RG.OUTCOME_AT + 3]), list(out[RG.RECORD_AT:out[RG.OUTCOME_AT + 1]])
                                    if out[RG.OUTCOME_AT] == RG.G_REJECT else [])
        return status, verdicts

    T.NativeTyping.check = checked
    analyze = CF.NativeCfg.analyze

    def analyzed(self, *args, **kwargs):
        result = analyze(self, *args, **kwargs)
        if frames and frames[-1]["uses"] is None:
            frames[-1]["uses"] = result[0] == 0 and bool(result[3])
        return result

    CF.NativeCfg.analyze = analyzed
    parse = X._parse_graph_uncached

    def parsed(obj, resolve):
        frames.append({"typing": None, "uses": None})
        try:
            graph = parse(obj, resolve)
            raised = None
        except X.XaxError as error:
            raised = error.diagnostic
            frame = frames.pop()
            compare(obj, frame, raised)
            raise
        frame = frames.pop()
        compare(obj, frame, None)
        return graph

    X._parse_graph_uncached = parsed


def compare(obj, frame, raised):
    from xax_selfhost_diagnostics import decode_record
    import xax_selfhost_render_graph as RG

    if not frame["uses"] or frame["typing"] is None or frame["typing"][0] != 0:
        STATS["skipped"] += 1
        return
    status, cursor, entity = frame["typing"][1]
    if status == RG.G_DECLINE:
        STATS["decline_rejected" if raised is not None else "decline_accepted"] += 1
        if raised is not None:
            DECLINED[raised.rule] = DECLINED.get(raised.rule, 0) + 1
        return
    if status == RG.G_ACCEPT:
        if raised is None:
            STATS["accept"] += 1
        else:
            STATS["diff"] += 1
            sys.stderr.write(f"\nGRAPH-DIFF accepted but the host raised {raised}\n")
        return
    words = frame["typing"][2]
    if entity == RG.ENTITY_GRAPH:
        code_end = 2 + (words[1] + 7) // 8
        words = [*words[:code_end], 4, *(int.from_bytes(obj.cid[k:k + 8], "big") for k in range(0, 32, 8)), *words[code_end:]]
    try:
        produced = decode_record(words)
    except Exception as error:  # noqa: BLE001 - a malformed record is a difference
        produced = f"undecodable: {error!r}"
    same = raised is not None and produced == raised and repr(produced) == repr(raised)
    if same:
        STATS["exact"] += 1
        RULES[raised.rule] = RULES.get(raised.rule, 0) + 1
    else:
        STATS["diff"] += 1
        sys.stderr.write(f"\nGRAPH-DIFF\n  xax={produced}\n  host={raised}\n")


def pytest_unconfigure(config):  # noqa: ARG001 - pytest hook
    sys.stderr.write(f"\nS15-GRAPH {STATS}\nS15-GRAPH exact {dict(sorted(RULES.items()))}\nS15-GRAPH declined {dict(sorted(DECLINED.items()))}\n")
