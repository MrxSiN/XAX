"""S4 evidence (ADR-132): XAX scalar typing rules on real program stores.

For each corpus store: covered nodes (scalar families), nodes the XAX
function proves, and ``verify_store`` wall time with the XAX path and with
``XAX_TYPING_PYTHON=1`` (bootstrap only), each in a fresh process so no parse
cache is shared.  Medians on this host; host-dependent.

Run: PYTHONPATH=src:. python -m benchmarks.bench_s4_typing
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent / "s4_typing_evidence.json"
CORPUS = {
    "jsonmin": "from benchmarks.jsonmin import build_jsonmin as b; reader = b().reader",
    "uniqcount": "from benchmarks.uniqcount import build_uniqcount as b; reader = b().reader",
    "blake3_selfhost": "from xax_compiler import StoreReader; from xax_selfhost_blake3 import STORE_PATH; reader = StoreReader(STORE_PATH.read_bytes())",
    "cfg_selfhost": "from xax_compiler import StoreReader; from xax_selfhost_cfg import STORE_PATH; reader = StoreReader(STORE_PATH.read_bytes())",
    "m14_selfhost_compiler": "from pathlib import Path; from xax_compiler import StoreReader; reader = StoreReader(Path('bootstrap/m14_selfhost_compiler.xax').read_bytes())",
}
PROBE = """
import json, statistics, time
{load}
import xax_compiler
from xax_compiler import Kind, verify_store
samples = []
for _ in range({repeats}):
    xax_compiler._PARSED_GRAPHS.clear()
    start = time.perf_counter(); verify_store(reader); samples.append(time.perf_counter() - start)
covered = proven = blocks = blocks_proven = constants = graphs = fact_free = calls = 0
native = xax_compiler._native_typing()
if native is not None:
    from xax_selfhost_typing import PROVEN, marshal, type_info_from
    from xax_compiler import Operation, _parse_graph, store_resolver
    resolve = store_resolver(reader)
    for item in reader.objects():
        if item.kind != Kind.GRAPH_FRAGMENT:
            continue
        parsed = _parse_graph(item, resolve)
        value_type = lambda b, v: parsed.blocks[v.block].parameters[v.index] if v.tag == 0 else parsed.blocks[v.block].nodes[v.index].results[v.result]
        words, keys = marshal(parsed.blocks, lambda b, n: parsed.blocks[b].nodes[n].operand_types, type_info_from(resolve), value_type)
        status, verdicts = native.check(words, len(keys) + len(parsed.blocks) + 1)
        covered += len(keys)
        blocks += len(parsed.blocks)
        graphs += 1
        if status == 0:
            proven += sum(v == PROVEN for v in verdicts[:len(keys)])
            blocks_proven += sum(v == PROVEN for v in verdicts[len(keys):-1])
            constants += sum(v == PROVEN and parsed.blocks[b].nodes[n].operation == Operation.CONSTANT for (b, n), v in zip(keys, verdicts))
            calls += sum(v == PROVEN and parsed.blocks[b].nodes[n].operation == Operation.CALL_DIRECT for (b, n), v in zip(keys, verdicts))
            fact_free += int(verdicts[-1] == 1 and sum(v == PROVEN for v in verdicts[:len(keys)]) == sum(len(x.nodes) for x in parsed.blocks) and all(v == PROVEN for v in verdicts[len(keys):-1]))
print(json.dumps({{"verify_ms": round(statistics.median(samples) * 1e3, 2), "covered": covered, "proven": proven, "blocks": blocks, "blocks_proven": blocks_proven, "constants": constants, "graphs": graphs, "fact_free": fact_free, "calls": calls}}))
"""


def _probe(load: str, python_only: bool, repeats: int = 7) -> dict:
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(("src", ".", "..")))
    if python_only:
        env["XAX_TYPING_PYTHON"] = "1"
    completed = subprocess.run([sys.executable, "-c", PROBE.format(load=load, repeats=repeats)], capture_output=True, text=True, check=True, env=env, cwd=Path(__file__).resolve().parents[1])
    return json.loads(completed.stdout.strip().splitlines()[-1])


def run() -> dict:
    rows = {}
    for name, load in CORPUS.items():
        native, bootstrap = _probe(load, False), _probe(load, True)
        rows[name] = {
            "covered_nodes": native["covered"],
            "proven_nodes": native["proven"],
            "proven_constant_nodes": native["constants"],
            "blocks": native["blocks"],
            "proven_terminators": native["blocks_proven"],
            "proven_call_contracts": native["calls"],
            "graphs": native["graphs"],
            "fact_free_graphs": native["fact_free"],
            "verify_ms_xax_typing": native["verify_ms"],
            "verify_ms_bootstrap_only": bootstrap["verify_ms"],
        }
    from xax_selfhost_typing import NativeTyping, STORE_PATH

    return {
        "step": "S4 to S4d.2a",
        "adr": "ADR-132 to ADR-136",
        "evidence_label": "MEASURED",
        "store_bytes": STORE_PATH.stat().st_size,
        "native_code_bytes": NativeTyping().code_size,
        "corpus": rows,
        "note": "verify_store medians over 7 runs in fresh processes; the graph parse cache is cleared before every run",
    }


def main() -> None:
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
