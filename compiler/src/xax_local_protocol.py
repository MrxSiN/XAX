"""Snapshot-bound fallback mutation transport for ordinary XAX workspaces.

This is tooling, not source. Short aliases abbreviate already exposed handles;
all omitted preconditions come from one immutable workspace snapshot.
"""

from __future__ import annotations

import hashlib
import re
import shlex

from xax_compiler import Operation, ValueRef, _decode_function_interface, _parse_graph, store_resolver
from xax_workspace import (
    ConnectEdgeArgument, DeleteNode, DisconnectEdgeArgument, InsertPureNode,
    MovePureNode, ReplaceUse, RootRef, SetConstant, SetFunctionSignature,
    SetOperation, SetResultType, Transaction, TransactionValueRef, Workspace,
)

BATCH_HELP = (
    "Separate edits with ;. Handles bind the pre-batch snapshot; insertion result @ID uses ID>=0."
)

# The complete, request-independent edit grammar (ADR-200). A client sends it
# once as shared context (system prompt, cached prefix, tool description) and
# then presents its identity instead of receiving per-request edit help.
_GRAMMAR_FORMS = (
    ("set-constant", "N INTEGER"),
    ("set-op", "N OP (OP: add.wrap, sub.wrap or mul.wrap)"),
    ("replace-operand", "N INDEX VALUE"),
    ("delete", "N"),
    ("prune-dead", "N (unused pure root and dead pure dependencies)"),
    ("move", "N before ANCHOR"),
    ("insert-constant", "ANCHOR ID INTEGER"),
    ("set-edge", "ANCHOR INTEGER_EDGE_INDEX INTEGER_ARG_INDEX VALUE"),
    ("set-type", "N NEW_TYPE (single-result node, or an entry parameter P)"),
    ("set-type", "N INTEGER_RESULT_INDEX NEW_TYPE"),
    ("set-type", "OLD_TYPE NEW_TYPE (every use of OLD_TYPE in the shown functions)"),
    ("set-type", "F OLD_TYPE NEW_TYPE (every use of OLD_TYPE in function F)"),
    ("set-signature", "F PARAM_TYPES RETURN_TYPES"),
)
_GRAMMAR_NOTES = (
    "Only handles shown in the snapshot are valid; a form that does not apply to them rejects.",
    "Values: N means result 0; N.Rk means result k; P0.. are parameters.",
    "Edge/argument indices start at 0; ANCHOR is the shown node in the source block.",
    "Type lists: comma-separated, - means empty. sig also retypes F's entry-block parameters.",
)


def edit_grammar(*, compact: bool = True) -> str:
    """The shared edit grammar. Deterministic: no snapshot, task or generation."""
    aliases = {verb: alias for alias, verb in COMPACT_VERBS.items()}
    forms = [f"- {aliases.get(verb, verb) if compact else verb} {fields}" for verb, fields in _GRAMMAR_FORMS]
    return "\n".join(["Edit forms (UPPERCASE words are values you supply):", *forms, *_GRAMMAR_NOTES, BATCH_HELP])


def edit_grammar_id(*, compact: bool = True) -> str:
    """Identity a client presents for the shared grammar it already holds."""
    return "xax-edit-" + hashlib.sha256(edit_grammar(compact=compact).encode()).hexdigest()[:12]

COMPACT_VERBS = {"const": "set-constant", "op": "set-op", "operand": "replace-operand",
                 "edge": "set-edge", "type": "set-type", "sig": "set-signature", "prune": "prune-dead"}

BOUND_FIELDS = {"set-constant": "INTEGER", "set-op": "add.wrap|sub.wrap|mul.wrap",
                "replace-operand": "INDEX VALUE", "move": "before ANCHOR",
                "set-edge": "EDGE_INDEX ARG_INDEX VALUE"}


def _implied_removed(mutations):
    """Drop edits a batch already implies (ADR-197): exact duplicates, and
    signature edits of one function that agree field by field merge into one.
    Disagreeing edits are kept, so the verifier still rejects the conflict."""
    unique = list(dict.fromkeys(mutations))
    signatures = {}
    for mutation in unique:
        if isinstance(mutation, SetFunctionSignature):
            signatures.setdefault(mutation.function, []).append(mutation)
    merged = {}
    for function, group in signatures.items():
        first = group[0]
        if len(group) == 1 or any((m.expected_parameters, m.expected_returns) != (first.expected_parameters, first.expected_returns) for m in group):
            continue
        def combine(old, news):
            out = []
            for index, item in enumerate(old):
                changes = {new[index] for new in news if len(new) == len(old) and new[index] != item}
                if len(changes) > 1 or any(len(new) != len(old) for new in news):
                    return None
                out.append(changes.pop() if changes else item)
            return tuple(out)
        parameters = combine(first.expected_parameters, [m.parameters for m in group])
        returns = combine(first.expected_returns, [m.returns for m in group])
        if parameters is not None and returns is not None:
            merged[function] = SetFunctionSignature(function, first.expected_parameters, parameters, first.expected_returns, returns)
    out, seen = [], set()
    for mutation in unique:
        if isinstance(mutation, SetFunctionSignature) and mutation.function in merged:
            if mutation.function not in seen:
                seen.add(mutation.function)
                out.append(merged[mutation.function])
            continue
        out.append(mutation)
    return tuple(out)


class LocalMutationSession:
    """Expand exact local edits without retransmitting known old attributes.

    Construct after the query supplying the model's view. Reuse this session
    for submission; never reconstruct it against a newer root to retry an edit.
    Workspace.commit still performs verification and the final atomic root check.
    """

    def __init__(self, workspace: Workspace, aliases: dict[str, str] | None = None, *, expected_generation: int | None = None):
        self.workspace = workspace
        with workspace._lock:
            if expected_generation is not None and workspace.generation != expected_generation:
                raise ValueError("stale local function query")
            self.snapshot = workspace._snapshot()
            self.generation = workspace.generation
        self.aliases = dict(aliases or {})
        self._bound = None
        bound = (self.snapshot.node_bindings | self.snapshot.function_bindings
                 | self.snapshot.value_bindings | self.snapshot.type_bindings)
        bound.update({handle.split(".B", 1)[0]: binding
                      for handle, binding in self.snapshot.node_bindings.items()})
        for alias, handle in self.aliases.items():
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9.]*", alias) or handle not in bound:
                raise ValueError("alias must abbreviate an exposed workspace handle")
        self.resolve = store_resolver(self.snapshot.reader)

    @classmethod
    def for_function(cls, workspace: Workspace, function_cid: bytes, limit: int = 64):
        """Bind a bounded selected function, including its unused parameters.

        N aliases follow node order and P aliases follow block/parameter order.
        A node used as a value abbreviates result zero; other results use the
        full exposed value handle. No task identity or expected edit is needed.
        """
        generation = workspace.generation
        page = workspace.function_nodes(function_cid, limit)
        if page.truncated:
            raise ValueError("selected function exceeds the local node budget")
        aliases = {f"N{i}": node.handle for i, node in enumerate(page.entities)}
        for node in page.entities:
            workspace.neighborhood(node.handle, node.operand_count + node.result_count or 1)
        for index, node in enumerate(page.entities):
            for result in range(node.result_count):
                handle = f"{node.handle}.R{result}"
                if handle in workspace._value_bindings:
                    aliases[f"N{index}.R{result}"] = handle
        resolve = store_resolver(workspace.reader)
        graph, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        parsed = _parse_graph(graph, resolve)
        if sum(len(block.parameters) for block in parsed.blocks) > limit:
            raise ValueError("selected function exceeds the local parameter budget")
        with workspace._lock:
            if workspace.generation != generation:
                raise ValueError("stale local function query")
            fn = workspace._function_handles[function_cid]
            workspace._function_bindings[fn] = (function_cid, generation)
            parameter = 0
            for block_index, block in enumerate(parsed.blocks):
                for index, type_cid in enumerate(block.parameters):
                    handle = f"{fn}.B{block_index}.P{index}"
                    workspace._value_bindings[handle] = (function_cid, ValueRef.parameter(block_index, index), generation)
                    workspace._type_bindings[workspace._type_handles[type_cid]] = (type_cid, generation)
                    aliases[f"P{parameter}"] = handle
                    parameter += 1
        return cls(workspace, aliases, expected_generation=generation)

    def _handle(self, text):
        if re.fullmatch(r"0|[1-9][0-9]*", text) and "N" + text in self.aliases:
            return self.aliases["N" + text]
        return self.aliases.get(text, text)

    def _node(self, text):
        handle = self._handle(text)
        binding = self.snapshot.node_bindings.get(handle)
        if binding is None or binding[3] != self.generation:
            aliases = sorted(alias for alias, target in self.aliases.items() if target in self.snapshot.node_bindings)
            kind = ("a function; use sig F PARAM_TYPES RETURN_TYPES" if handle in self.snapshot.function_bindings else
                    "a type" if handle in self.snapshot.type_bindings else
                    "a parameter" if handle in self.snapshot.value_bindings else "not a shown handle")
            raise ValueError(f"{text} is {kind}, not a node; node aliases: {','.join(aliases)}")
        cid, block, index, _ = binding
        graph, _, _ = _decode_function_interface(self.resolve(cid), self.resolve)
        return handle, block, index, _parse_graph(graph, self.resolve).blocks[block].nodes[index]

    def _value(self, text, owner):
        if re.fullmatch(r"@(?:0|[1-9][0-9]*)", text):
            return TransactionValueRef(int(text[1:]))
        handle = self._handle(text)
        binding = self.snapshot.value_bindings.get(handle)
        if binding is not None and binding[2] == self.generation:
            if binding[0] != owner:
                raise ValueError("value belongs to another function")
            return binding[1]
        node_handle, block, index, node = self._node(text)
        if self.snapshot.node_bindings[node_handle][0] != owner:
            raise ValueError("value belongs to another function")
        if not node.results:
            raise ValueError("node has no result")
        return ValueRef.node_result(block, index)

    def _type(self, text):
        handle = self.aliases.get("T" + text, "T" + text) if re.fullmatch(r"0|[1-9][0-9]*", text) else self._handle(text)
        binding = self.snapshot.type_bindings.get(handle)
        if binding is None or binding[1] != self.generation:
            raise ValueError(f"unexposed type: {text}")
        return handle

    def _types(self, text):
        return () if text == "-" else tuple(self._type(item) for item in text.split(","))

    @staticmethod
    def _index(text, *prefixes):
        for prefix in prefixes:
            if re.fullmatch(re.escape(prefix) + r"(?:0|[1-9][0-9]*)", text):
                return int(text[len(prefix):])
        return int(text)

    def _function(self, text):
        handle = self.aliases.get("F" + text, "F" + text) if re.fullmatch(r"0|[1-9][0-9]*", text) else self._handle(text)
        binding = self.snapshot.function_bindings.get(handle)
        if binding is None:
            binding = next(((value[0], value[3]) for key, value in self.snapshot.node_bindings.items() if key.startswith(handle + ".B")), None)
        if binding is None or binding[1] != self.generation:
            raise ValueError("unexposed function")
        return handle, binding[0]

    def _bound_types(self, cids):
        handles = []
        for cid in cids:
            handle = next((key for key, value in self.snapshot.type_bindings.items() if value == (cid, self.generation)), None)
            if handle is None:
                raise ValueError("unexposed existing interface type")
            handles.append(handle)
        return tuple(handles)

    def _retype(self, old, new, only=None):
        """`type T NEW`: every use of T in the shown functions (or only in
        function `only`), expanded into the ordinary result-type and signature
        mutations (ADR-197). Shown functions own an aliased node or value;
        nothing outside them changes."""
        old_cid = self.snapshot.type_bindings[old][0]
        shown = set(self.aliases.values())
        owners = ({b[0] for h, b in self.snapshot.node_bindings.items() if h in shown}
                  | {b[0] for h, b in self.snapshot.value_bindings.items() if h in shown})
        if only is not None:
            if only not in owners:
                raise ValueError("function is not shown")
            owners = {only}
        nodes = {b[:3]: h for h, b in self.snapshot.node_bindings.items()}
        mutations = []
        for owner in sorted(owners, key=lambda cid: self.workspace._function_handles[cid]):
            graph, parameters, returns = _decode_function_interface(self.resolve(owner), self.resolve)
            parsed = _parse_graph(graph, self.resolve)
            for block_index, block in enumerate(parsed.blocks):
                if block_index != parsed.entry and old_cid in block.parameters:
                    raise ValueError("retype cannot change a non-entry block parameter; edit it explicitly")
                for node_index, node in enumerate(block.nodes):
                    for result, cid in enumerate(node.results):
                        if cid == old_cid:
                            mutations.append(SetResultType(nodes[(owner, block_index, node_index)], result, old, new))
            if old_cid in parameters or old_cid in returns:
                handle = self.workspace._function_handles[owner]
                old_parameters, old_returns = self._bound_types(parameters), self._bound_types(returns)
                swap = lambda handles: tuple(new if item == old else item for item in handles)
                mutations.append(SetFunctionSignature(handle, old_parameters, swap(old_parameters), old_returns, swap(old_returns)))
        if not mutations:
            raise ValueError(f"type {old} is not used in the shown functions")
        return mutations

    def _dead_closure(self, handle, owner, block, index):
        graph = _parse_graph(_decode_function_interface(self.resolve(owner), self.resolve)[0], self.resolve)
        nodes = {(bi, ni): node for bi, item in enumerate(graph.blocks) for ni, node in enumerate(item.nodes)}
        users = {position: set() for position in nodes}
        for position, node in nodes.items():
            for operand in node.operands:
                if operand.tag == 1:
                    users[(operand.block, operand.index)].add(position)
        for item in graph.blocks:
            for value in (*item.terminator.values, *(value for _, args in item.terminator.edges for value in args)):
                if value.tag == 1:
                    users[(value.block, value.index)].add(None)
        pure = {Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP}
        root = (block, index)
        if nodes[root].operation not in pure or users[root]:
            raise ValueError("prune-dead requires an unused supported pure node")
        deleted = {root}
        while True:
            dependencies = {(value.block, value.index) for position in deleted for value in nodes[position].operands if value.tag == 1}
            additions = {position for position in dependencies-deleted if nodes[position].operation in pure and users[position] <= deleted}
            if not additions:
                break
            deleted.update(additions)
        mutations = []
        for bi, ni in sorted(deleted):
            target = next((key for key, binding in self.snapshot.node_bindings.items() if binding == (owner, bi, ni, self.generation)), None)
            if target is None:
                raise ValueError("dead closure exceeds the exposed neighborhood")
            mutations.append(DeleteNode(target, bi, ni))
        return mutations

    def transaction(self, command: str) -> Transaction:
        mutations = []
        for record in command.split(";"):
            parts = shlex.split(record)
            if not parts:
                raise ValueError("empty mutation")
            verb, *args = parts
            verb = COMPACT_VERBS.get(verb, verb)
            if verb == "signature" and len(args) == 5 or verb == "set-signature" and len(args) == 3:
                handle, owner = self._function(args[0])
                if verb == "signature":
                    mutation = SetFunctionSignature(handle, *(self._types(a) for a in args[1:]))
                else:
                    _, parameters, returns = _decode_function_interface(self.resolve(owner), self.resolve)
                    mutation = SetFunctionSignature(handle, self._bound_types(parameters), self._types(args[1]),
                                                    self._bound_types(returns), self._types(args[2]))
                mutations.append(mutation)
                continue
            if not args:
                raise ValueError("mutation requires a node")
            if verb == "set-type" and len(args) == 3 and self._handle(args[0]) in self.snapshot.function_bindings:
                mutations.extend(self._retype(self._type(args[1]), self._type(args[2]), self._function(args[0])[1]))
                continue
            if verb == "set-type" and len(args) == 2 and self._handle(args[0]) in self.snapshot.type_bindings:
                mutations.extend(self._retype(self._type(args[0]), self._type(args[1])))
                continue
            if verb == "set-type" and len(args) == 2 and self._handle(args[0]) in self.snapshot.value_bindings:
                # An entry parameter's type is its function's signature parameter.
                owner, value, _ = self.snapshot.value_bindings[self._handle(args[0])]
                graph, parameters, returns = _decode_function_interface(self.resolve(owner), self.resolve)
                if value.tag != 0 or value.block != _parse_graph(graph, self.resolve).entry:
                    raise ValueError("only entry-block parameters can be retyped; use the edge's block signature")
                old = self._bound_types(parameters)
                new = tuple(self._type(args[1]) if i == value.index else item for i, item in enumerate(old))
                mutations.append(SetFunctionSignature(self.workspace._function_handles[owner], old, new, self._bound_types(returns), self._bound_types(returns)))
                continue
            handle, block, index, node = self._node(args[0])
            owner = self.snapshot.node_bindings[handle][0]
            if verb == "set-constant" and len(args) == 2:
                from xax_compiler import _decode_constant
                if node.operation != Operation.CONSTANT:
                    raise ValueError("constant node required")
                value = _decode_constant(node.entity, self.resolve)[1]
                mutation = SetConstant(handle, value, int(args[1]))
            elif verb == "set-op" and len(args) == 2:
                try:
                    operation = Operation[args[1].upper().replace(".", "_")]
                except KeyError as error:
                    raise ValueError("unknown operation") from error
                mutation = SetOperation(handle, Operation(node.operation), operation)
            elif verb == "replace-operand" and len(args) == 3:
                operand = self._index(args[1], "operand", "arg")
                if not 0 <= operand < len(node.operands):
                    raise ValueError("operand index outside node")
                mutation = ReplaceUse(handle, operand, node.operands[operand], self._value(args[2], owner))
            elif verb == "delete" and len(args) == 1:
                mutation = DeleteNode(handle, block, index)
            elif verb == "prune-dead" and len(args) == 1:
                mutations.extend(self._dead_closure(handle, owner, block, index))
                continue
            elif verb == "move" and len(args) == 3 and args[1] == "before":
                destination, db, di, _ = self._node(args[2])
                mutation = MovePureNode(handle, block, index, destination, db, di)
            elif verb == "insert-constant" and len(args) == 3:
                if len(node.results) != 1:
                    raise ValueError("single-result typed anchor required")
                type_handle = next(k for k, v in self.snapshot.type_bindings.items() if v[0] == node.results[0])
                self._type(type_handle)
                mutation = InsertPureNode(handle, block, index, int(args[1]), Operation.CONSTANT,
                                          (), type_handle, int(args[2]))
            elif verb in {"disconnect-edge", "connect-edge"} and len(args) == 4:
                value = self._value(args[3], owner)
                if verb == "disconnect-edge" and isinstance(value, TransactionValueRef):
                    raise ValueError("existing edge value required")
                carrier = DisconnectEdgeArgument if verb == "disconnect-edge" else ConnectEdgeArgument
                mutation = carrier(handle, block, self._index(args[1], "edge"), self._index(args[2], "arg"), value)
            elif verb == "set-edge" and len(args) == 4:
                edge, argument = self._index(args[1], "edge"), self._index(args[2], "arg")
                graph = _parse_graph(_decode_function_interface(self.resolve(owner), self.resolve)[0], self.resolve)
                edges = graph.blocks[block].terminator.edges
                if not 0 <= edge < len(edges) or not 0 <= argument < len(edges[edge][1]):
                    raise ValueError("edge and argument indices must be valid zero-based integers")
                old = edges[edge][1][argument]
                new = self._value(args[3], owner)
                mutations.extend((DisconnectEdgeArgument(handle, block, edge, argument, old), ConnectEdgeArgument(handle, block, edge, argument, new)))
                continue
            elif verb == "result-type" and len(args) == 4:
                mutation = SetResultType(handle, self._index(args[1], "R", "result"), self._type(args[2]), self._type(args[3]))
            elif verb == "set-type" and len(args) in (2, 3):
                if len(args) == 2 and len(node.results) != 1:
                    raise ValueError("multi-result nodes require an integer result index")
                result = self._index(args[1], "R", "result") if len(args) == 3 else 0
                if not 0 <= result < len(node.results):
                    raise ValueError("result index outside node")
                mutation = SetResultType(handle, result, self._bound_types((node.results[result],))[0], self._type(args[-1]))
            else:
                raise ValueError("unsupported mutation or arity")
            mutations.append(mutation)
        return Transaction(RootRef(self.generation), _implied_removed(mutations))

    def commit(self, command: str):
        return self.workspace.commit(self.transaction(command))

    def bind(self, verb: str, node: str) -> str:
        """Bind a caller-selected kind/target, never a replacement value."""
        verb = COMPACT_VERBS.get(verb, verb)
        if verb not in BOUND_FIELDS:
            raise ValueError("mutation has no supported remaining fields")
        handle = self._node(node)[0]
        binding = (verb, node, handle)
        with self.workspace._lock:
            if self._bound is not None and self._bound != binding:
                raise ValueError("binding already fixed; use a new session")
            self._bound = binding
        return f"Bound {verb} {node}; reply with {BOUND_FIELDS[verb]} or its matching full command. Handles use the pre-batch snapshot."

    def commit_bound(self, response: str):
        if self._bound is None:
            raise ValueError("no bound mutation")
        verb, node, handle = self._bound
        fields = shlex.split(response)
        if self._handle(node) != handle:
            raise ValueError("bound target alias changed")
        arity = len(BOUND_FIELDS[verb].split())
        if (len(fields) == arity + 2 and COMPACT_VERBS.get(fields[0], fields[0]) == verb
                and self._handle(fields[1]) == handle):
            fields = fields[2:]
        if ';' in response or len(fields) != arity:
            raise ValueError(f"return only {BOUND_FIELDS[verb]}")
        return self.commit(shlex.join((verb, node, *fields)))

    def instructions(self, *, compact: bool = True, shared: str | None = None) -> str:
        """Advertise mutation carriers applicable to the exposed neighborhood.

        With `shared`, the client states that it already holds the shared
        grammar of that identity: the per-request help is then empty. A stale
        or foreign identity rejects instead of silently mixing grammars."""
        if shared is not None:
            if shared != edit_grammar_id(compact=compact):
                raise ValueError(f"stale shared edit grammar {shared}; current is {edit_grammar_id(compact=compact)}")
            return ""
        from xax_compiler import Cursor
        nodes = [self._node(handle)[3] for handle in self.snapshot.node_bindings]
        operations = {node.operation for node in nodes}
        forms = []
        if Operation.CONSTANT in operations:
            forms.append("set-constant N INTEGER")
        if operations & {Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP}:
            forms.append("set-op N OP (OP: add.wrap, sub.wrap or mul.wrap)")
        if any(node.operands for node in nodes):
            forms.append("replace-operand N INDEX VALUE")
        pure = {Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP}
        if operations & pure:
            forms.append("delete N")
            for handle, binding in self.snapshot.node_bindings.items():
                if self._node(handle)[3].operation not in pure:
                    continue
                try:
                    self._dead_closure(handle, binding[0], binding[1], binding[2])
                    forms.append("prune-dead N (unused pure root and dead pure dependencies)")
                    break
                except ValueError:
                    pass
        if len(nodes) > 1 and operations & pure:
            forms.append("move N before ANCHOR")
        if any(len(node.results) == 1 and Cursor(self.resolve(node.results[0]).body, "type").uleb() == 1 for node in nodes):
            forms.append("insert-constant ANCHOR ID INTEGER")
        functions = {binding[0] for binding in self.snapshot.node_bindings.values()}
        has_edges = any(block.terminator.edges for cid in functions
                        for block in _parse_graph(_decode_function_interface(self.resolve(cid), self.resolve)[0], self.resolve).blocks)
        if has_edges:
            forms.append("set-edge ANCHOR INTEGER_EDGE_INDEX INTEGER_ARG_INDEX VALUE")
        type_forms = [Cursor(self.resolve(binding[0]).body, "type").uleb() for binding in self.snapshot.type_bindings.values()]
        type_changes = len(type_forms) > len(set(type_forms))
        if type_changes:
            forms.extend(("set-type N NEW_TYPE" if all(len(node.results) == 1 for node in nodes) else "set-type N INTEGER_RESULT_INDEX NEW_TYPE",
                          "set-type OLD_TYPE NEW_TYPE (every use of OLD_TYPE in the shown functions)",
                          "set-type F OLD_TYPE NEW_TYPE (every use of OLD_TYPE in function F)",
                          "set-signature F PARAM_TYPES RETURN_TYPES"))
        type_help = " Type lists: comma-separated, - means empty. sig also retypes F's entry-block parameters." if type_changes else ""
        edge_help = " Edge/argument indices start at 0; ANCHOR is the shown node in the source block." if has_edges else ""
        value_help = " Values: N means result 0; N.Rk means result k." if any(len(node.results) > 1 for node in nodes) else ""
        if compact:
            aliases = {verb: alias for alias, verb in COMPACT_VERBS.items()}
            forms = [aliases.get(form.split(' ', 1)[0], form.split(' ', 1)[0]) + ' ' + form.split(' ', 1)[1] for form in forms]
        # One form per line, placeholders named as such: weaker models read an
        # inline `a | b` grammar as literal output (ADR-196).
        notes = (type_help + edge_help + value_help).strip()
        return "\n".join(["Edit forms (UPPERCASE words are values you supply):", *("- " + form for form in forms),
                          *([notes] if notes else []), BATCH_HELP])

    def diagnostic_view(self, diagnostic) -> dict:
        """Project a verifier rejection onto already exposed local identities."""
        reverse = {handle: alias for alias, handle in self.aliases.items()}
        def short(handle):
            label = reverse.get(handle, handle)
            return label if self._handle(label) == handle else "unexposed entity"
        identities = {self.snapshot.root.hex(): "R0"}
        for handle, binding in self.snapshot.type_bindings.items():
            identities[binding[0].hex()] = short(handle)
        for handle, binding in self.snapshot.function_bindings.items():
            identities[binding[0].hex()] = short(handle)
            graph = _decode_function_interface(self.resolve(binding[0]), self.resolve)[0]
            identities[graph.cid.hex()] = short(handle)
        def project(value):
            if isinstance(value, bytes):
                return identities.get(value.hex(), "unexposed identity")
            if isinstance(value, str):
                return identities.get(value, short(value))
            if isinstance(value, (tuple, list)):
                return [project(item) for item in value]
            if isinstance(value, dict):
                return {key: project(item) for key, item in value.items()}
            return value
        return {"code": diagnostic.code, "entity": project(diagnostic.entity), "rule": diagnostic.rule,
                "expected": project(diagnostic.expected), "actual": project(diagnostic.actual),
                "repair": project(diagnostic.repair_neighborhood)}

    def view(self, *, functions: tuple[bytes, ...] | None = None, bound: bool = False) -> str:
        """Project the bound functions from this snapshot, with no task knowledge.

        Includes operands, result types, attributes, entity bindings, and control
        edges. Only functions whose entire node set is exposed may be projected.
        """
        from xax_compiler import _decode_constant, decode_bits_width, XaxError, Cursor, _decode_effect_type, _decode_resource_type
        reverse = {handle: alias for alias, handle in self.aliases.items()}
        def short(handle):
            return reverse.get(handle, handle)
        types = {binding[0]: short(handle) for handle, binding in self.snapshot.type_bindings.items()}
        owners = {binding[0] for binding in self.snapshot.function_bindings.values()}
        owners.update(binding[0] for binding in self.snapshot.node_bindings.values())
        if functions is not None:
            if not set(functions) <= owners:
                raise ValueError("unexposed function in projection")
            owners = set(functions)
        if bound:
            if self._bound is None:
                raise ValueError("no bound mutation")
            verb, target, handle = self._bound
            if self._handle(target) != handle:
                raise ValueError("bound target alias changed")
            if self.snapshot.node_bindings[handle][0] not in owners:
                raise ValueError("bound node outside selected functions")
            node = self._node(target)[3]
            scalar = (verb == "set-constant" and node.operation == Operation.CONSTANT or
                      verb == "set-op" and node.operation in {Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP})
            if scalar and len(node.results) == 1:
                width = decode_bits_width(self.resolve(node.results[0]))
                operation = Operation(node.operation).name.lower().replace('_', '.')
                value = f" {_decode_constant(node.entity, self.resolve)[1]}" if node.operation == Operation.CONSTANT else ""
                self.last_view_entities = 3  # root, selected node, integer type
                return f"R0.{self.generation}\n{target} {operation}{value} bits{width}"
        function_labels = {}
        for cid in owners:
            handles = [handle for handle, binding in self.snapshot.function_bindings.items() if binding[0] == cid]
            if not handles:
                handles = [handle.split(".B", 1)[0] for handle, binding in self.snapshot.node_bindings.items() if binding[0] == cid]
            function_labels[cid] = short(handles[0])
        if len(set(function_labels.values())) != len(function_labels):
            raise ValueError("function aliases collide; select functions or bind unique aliases")
        lines = [f"R0.{self.generation}"]
        entity_count = 1 + len(function_labels) + len(types)
        for cid, alias in sorted(function_labels.items(), key=lambda item: item[1]):
            graph, params, returns = _decode_function_interface(self.resolve(cid), self.resolve)
            parsed = _parse_graph(graph, self.resolve)
            result_types = {node.results for block in parsed.blocks for node in block.nodes}
            default_results = next(iter(result_types)) if len(result_types) == 1 else ()
            default_results = default_results if len(default_results) == 1 else ()
            def ref(value):
                if value.tag == 0:
                    match = next((h for h, b in self.snapshot.value_bindings.items() if b[0] == cid and b[1] == value), None)
                    if match is None:
                        raise ValueError("unexposed parameter in projection")
                    return short(match)
                match = next((h for h, b in self.snapshot.node_bindings.items() if b[:3] == (cid, value.block, value.index)), None)
                if match is None:
                    raise ValueError("incomplete node projection")
                return short(match) if value.result == 0 else short(f"{match}.R{value.result}")
            lines.append(f"{alias}({','.join(types[t] for t in params)})->({','.join(types[t] for t in returns)})")
            if default_results:
                lines.append(f"node results=({types[default_results[0]]})")
            for bi, block in enumerate(parsed.blocks):
                entity_count += 1 + len(block.parameters) + len(block.nodes)
                parameters = ','.join(f"{ref(ValueRef.parameter(bi, i))}:{types[t]}" for i, t in enumerate(block.parameters))
                lines.append(f"B{bi}({parameters})")
                for ni, node in enumerate(block.nodes):
                    label = ref(ValueRef.node_result(bi, ni))
                    if node.operation == Operation.CONSTANT:
                        operation = f"constant {_decode_constant(node.entity, self.resolve)[1]}"
                    else:
                        operation = Operation(node.operation).name.lower().replace('_', '.')
                    entity = ""
                    if node.entity is not None and node.operation != Operation.CONSTANT:
                        entity = " entity=" + function_labels.get(node.entity.cid, "external")
                    attributes = f" attributes={node.attributes}" if node.attributes else ""
                    operands = ' '.join(ref(v) for v in node.operands)
                    results = "" if default_results else f" -> ({','.join(types[t] for t in node.results)})"
                    lines.append(f"{label} {operation}{' ' + operands if operands else ''}{results}{entity}{attributes}")
                term = block.terminator
                edges = ' '.join(f"edge{i}=B{dest}({','.join(ref(v) for v in args)})" for i, (dest, args) in enumerate(term.edges))
                anchor = " anchor=" + ref(ValueRef.node_result(bi, 0)) if term.edges and block.nodes else ""
                lines.append(f"{term.kind.name.lower()} {' '.join(ref(v) for v in term.values)} {edges}{anchor}".rstrip())
        for cid, handle in sorted(types.items(), key=lambda item: item[1]):
            try:
                description = f"bits{decode_bits_width(self.resolve(cid))}"
            except XaxError:
                obj = self.resolve(cid)
                form = Cursor(obj.body, "type").uleb()
                if form == 3:
                    effect = _decode_effect_type(obj)
                    description = f"effect {effect.domain.name.lower()} instance={effect.instance}"
                elif form == 4:
                    resource = _decode_resource_type(obj)
                    description = f"resource kind={resource.kind} state={resource.state} flags={int(resource.flags)} instance={resource.instance} transitions={resource.transitions}"
                else:
                    description = "non-integer type (identity preserved)"
            lines.append(f"{handle} {description}")
        self.last_view_entities = entity_count
        return '\n'.join(lines)


def construct_program(request: dict, *, limit: int = 64):
    """Decode a bounded, typed construction-tool request into canonical state.

    Aliases are request-local and never enter semantic identity. This adapter
    constructs one straight-line integer function; GraphBuilder remains the
    general construction API. No expected program or task identity is supplied.
    The return value is a verified StoreReader, not an alternative source form.
    """
    from xax_compiler import Kind, bits_type, object_with_refs, verify_store, write_store, StoreReader
    from xax_graph_builder import GraphBuilder

    if not isinstance(request, dict) or set(request) != {"parameters", "returns", "nodes", "return"}:
        raise ValueError("construction requires parameters, returns, nodes, return")
    if limit < 1 or any(not isinstance(request[key], list) or len(request[key]) > limit for key in request):
        raise ValueError("construction exceeds bounds or contains a non-list field")
    def type_object(width):
        if type(width) is not int or width < 1:
            raise ValueError("positive integer bit width required")
        return bits_type(width)
    graph = GraphBuilder()
    parameters = tuple(type_object(width) for width in request["parameters"])
    returns = tuple(type_object(width) for width in request["returns"])
    block = graph.block(*parameters)
    values = {f"P{i}": value for i, value in enumerate(block.params)}
    def value(alias):
        if not isinstance(alias, str) or alias not in values:
            raise ValueError("unbound construction value")
        return values[alias]
    for index, record in enumerate(request["nodes"]):
        if not isinstance(record, list) or len(record) < 2 or not isinstance(record[0], str):
            raise ValueError("node requires operation and result width")
        operation = Operation[record[0].upper().replace(".", "_")]
        result_type = type_object(record[1])
        if operation == Operation.CONSTANT:
            if len(record) != 3 or type(record[2]) is not int:
                raise ValueError("constant requires one integer value")
            result = block.const(result_type, record[2])
        else:
            result = block.op1(operation, tuple(value(alias) for alias in record[2:]), result_type)
        values[f"@{index}"] = result
    block.ret(*(value(alias) for alias in request["return"]))
    entry = graph.function(parameters, returns)
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*graph.objects.values(), module, root)))
    verify_store(reader)
    return reader
