"""OI-03 recursion-carrier size comparison (tooling-only evidence).

Three workloads over the same eight function bodies ``x * k + c``:

* ``none``: eight non-recursive leaf functions.  Arms: ``function`` (direct
  carrier) and ``singleton_group`` (measurement-only: each wrapped in a
  one-member ``recursion_group``, which the verifier rejects as not recursive).
* ``self``: eight self-recursive singletons.  Arms: ``group`` (current
  carrier) and ``compact_singleton`` (measurement-only: the group body with the
  member count omitted; never verified or executed).
* ``mutual``: the eight functions arranged as recursive rings of size 2, 2 and
  4, each in canonical member order.  Arms: ``group`` (current carrier) and ``per_member`` (measurement-only:
  one ``function`` envelope per member graph, i.e. what the members would cost
  as separate objects if CID cycles were allowed; never verified).

Legal arms are whole-store verified and executed against a reference value.
Token counts are offline tiktoken counts of the hex carrier envelopes and of
persistent entity handles (``cid`` or ``cid#member``); no model is run.
Everything recorded is deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path

from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    RecursionMember,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    canonical_recursion_order,
    constant,
    execute,
    execute_group_member,
    function,
    graph_fragment,
    object_with_refs,
    recursion_group,
    verify_store,
    write_store,
)


OUTPUT = Path(__file__).resolve().parent / "oi03_recursion_evidence.json"
B1, B64 = bits_type(1), bits_type(64)
MASK = (1 << 64) - 1
COUNT = 8
ENCODINGS = ("cl100k_base", "o200k_base")


def constants(i: int) -> tuple[int, int]:
    return i * 31 + 3, i % 3 + 2


def leaf_graph(i: int) -> tuple[SemanticObject, list[SemanticObject]]:
    """``f(a, b) = (a + b) * k + c``."""
    c, k = constants(i)
    ck, cc = constant(B64, k), constant(B64, c)
    a, b = ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)
    nodes = (
        Node(Operation.ADD_WRAP, (a, b), (B64,)),
        Node(Operation.CONSTANT, (), (B64,), entity=ck),
        Node(Operation.MUL_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (B64,)),
        Node(Operation.CONSTANT, (), (B64,), entity=cc),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 3)), (B64,)),
    )
    graph = graph_fragment([Block((B64, B64), nodes, Terminator.return_((ValueRef.node_result(0, 4),)))])
    return graph, [ck, cc, graph]


def recursive_graph(i: int, callee: int) -> tuple[SemanticObject, list[SemanticObject]]:
    """``f(done, x) = done ? x * k + c : member[callee](1, x)``."""
    c, k = constants(i)
    ck, cc, one = constant(B64, k), constant(B64, c), constant(B1, 1)
    done, x = ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)
    finish = Block(
        (B64,),
        (
            Node(Operation.CONSTANT, (), (B64,), entity=ck),
            Node(Operation.MUL_WRAP, (ValueRef.parameter(1, 0), ValueRef.node_result(1, 0)), (B64,)),
            Node(Operation.CONSTANT, (), (B64,), entity=cc),
            Node(Operation.ADD_WRAP, (ValueRef.node_result(1, 1), ValueRef.node_result(1, 2)), (B64,)),
        ),
        Terminator.return_((ValueRef.node_result(1, 3),)),
    )
    recurse = Block(
        (B64,),
        (
            Node(Operation.CONSTANT, (), (B1,), entity=one),
            Node(Operation.CALL_GROUP_MEMBER, (ValueRef.node_result(2, 0), ValueRef.parameter(2, 0)), (B64,), member=callee),
        ),
        Terminator.return_((ValueRef.node_result(2, 1),)),
    )
    entry = Block((B1, B64), (), Terminator.conditional_branch(done, 1, (x,), 2, (x,)))
    graph = graph_fragment([entry, finish, recurse])
    return graph, [B1, ck, cc, one, graph]


def reference(i: int, x: int) -> int:
    c, k = constants(i)
    return (x * k + c) & MASK


# ---------------------------------------------------------------- workloads

def workload(name: str, arm: str) -> dict:
    """Return carriers, the full object list, entity handles and legality."""
    objects: dict[bytes, SemanticObject] = {B64.cid: B64}
    carriers: list[SemanticObject] = []
    handles: list[tuple[SemanticObject, int | None, int]] = []  # (carrier, member, function whose value it returns)

    def keep(items):
        objects.update((o.cid, o) for o in items)

    if name == "none":
        for i in range(COUNT):
            graph, owned = leaf_graph(i)
            keep(owned)
            if arm == "function":
                carrier = function(graph, (B64, B64), (B64,))
                handles.append((carrier, None, i))
            else:
                carrier = recursion_group([RecursionMember(graph, (B64, B64), (B64,))])
                handles.append((carrier, 0, i))
            carriers.append(carrier)
    else:
        start = 0
        for size in ring_sizes(name):
            def ring(order, sink):
                position = {old: new for new, old in enumerate(order)}
                members = []
                for old in order:
                    graph, owned = recursive_graph(start + old, position[(old + 1) % size])
                    sink.update((o.cid, o) for o in owned)
                    members.append(RecursionMember(graph, (B1, B64), (B64,)))
                return members

            draft = {B64.cid: B64}
            order = canonical_recursion_order(ring(range(size), draft), draft.__getitem__)
            members = ring(order, objects)
            if arm == "group":
                carrier = recursion_group(members)
                carriers.append(carrier)
                handles.extend((carrier, new, start + (old + 1) % size) for new, old in enumerate(order))
            elif arm == "compact_singleton":
                full = recursion_group(members)
                carrier = SemanticObject.create(Kind.RECURSION_GROUP, full.body[1:], full.references)
                carriers.append(carrier)
                handles.append((carrier, None, start))
            else:  # per_member
                for member, old in zip(members, order):
                    carrier = function(member.graph, member.parameters, member.returns)
                    carriers.append(carrier)
                    handles.append((carrier, None, start + old))
            start += size
    keep(carriers)
    module = object_with_refs(Kind.MODULE, carriers)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    keep((module, root))
    legal = (name, arm) in {("none", "function"), ("self", "group"), ("mutual", "group")}
    return {"root": root, "objects": list(objects.values()), "carriers": carriers, "handles": handles, "legal": legal}


def ring_sizes(name: str) -> list[int]:
    return [1] * COUNT if name == "self" else [2, 2, 4] if name == "mutual" else []


def handle_text(carrier: SemanticObject, member: int | None) -> str:
    return carrier.cid.hex() if member is None else f"{carrier.cid.hex()}#{member}"


def check_legal(w: dict, name: str) -> None:
    """Whole-store verify and execute every entity against the reference."""
    reader = StoreReader(write_store(w["root"].cid, w["objects"]))
    verify_store(reader)
    for carrier, member, fn in w["handles"]:
        if member is None:
            got, want = execute(reader, carrier.cid, (5, 6)), reference(fn, 11)
        else:
            # done=0 recurses once into the ring successor, which finishes.
            got, want = execute_group_member(reader, carrier.cid, member, (0, 7)), reference(fn, 7)
        if got != (want,):
            raise AssertionError((name, carrier.cid.hex(), member, got, want))


ARMS = {"none": ("function", "singleton_group"), "self": ("group", "compact_singleton"), "mutual": ("group", "per_member")}


def measure(name: str, arm: str, tokenizers: dict) -> dict:
    w = workload(name, arm)
    if w["legal"]:
        check_legal(w, name)
    store = write_store(w["root"].cid, w["objects"])
    envelopes = [c.envelope() for c in w["carriers"]]
    carrier_hex = "\n".join(e.hex() for e in envelopes)
    handles = "\n".join(handle_text(c, m) for c, m, _ in w["handles"])
    return {
        "legal": w["legal"],
        "entities": len(w["handles"]),
        "carrier_objects": len(w["carriers"]),
        "carrier_bytes": sum(map(len, envelopes)),
        "carrier_body_bytes": sum(len(c.body) for c in w["carriers"]),
        "store_objects": len(w["objects"]),
        "store_bytes": len(store),
        "carrier_hex_tokens": {n: len(t.encode(carrier_hex)) for n, t in tokenizers.items()},
        "handle_tokens": {n: len(t.encode(handles)) for n, t in tokenizers.items()},
    }


def edit_churn(name: str, arm: str, target: int) -> dict:
    """Change function ``target``'s ``c``; count rewritten objects and entity identities."""
    global constants
    base = workload(name, arm)
    original = constants
    try:
        constants = lambda i: (999, 2) if i == target else original(i)
        edited = workload(name, arm)
    finally:
        constants = original
    old = {o.cid for o in base["objects"]}
    new_objects = [o for o in edited["objects"] if o.cid not in old]
    old_ids = {handle_text(c, m) for c, m, _ in base["handles"]}
    changed_ids = sum(handle_text(c, m) not in old_ids for c, m, _ in edited["handles"])
    return {
        "rewritten_objects": len(new_objects),
        "rewritten_bytes": sum(len(o.envelope()) for o in new_objects),
        "changed_entity_identities": changed_ids,
    }


def run() -> dict:
    import tiktoken

    tokenizers = {n: tiktoken.get_encoding(n) for n in ENCODINGS}
    results = {}
    for name, arms in ARMS.items():
        for arm in arms:
            row = measure(name, arm, tokenizers)
            row["edit_first"] = edit_churn(name, arm, 0)
            row["edit_last"] = edit_churn(name, arm, COUNT - 1)
            results[f"{name}/{arm}"] = row
    return {
        "issue": "OI-03",
        "tokenizer": f"tiktoken {tiktoken.__version__}",
        "model_run": None,
        "functions_per_workload": COUNT,
        "mutual_ring_sizes": ring_sizes("mutual"),
        "results": results,
    }


def main() -> None:
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for key, row in result["results"].items():
        print(f"{key:26} legal={row['legal']!s:5} carriers={row['carrier_objects']:2} "
              f"carrier_B={row['carrier_bytes']:5} store_B={row['store_bytes']:5} "
              f"hex_tok={row['carrier_hex_tokens']['o200k_base']:5} handle_tok={row['handle_tokens']['o200k_base']:4} "
              f"edit_last={row['edit_last']}")


if __name__ == "__main__":
    main()
