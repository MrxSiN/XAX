"""OI-54 step 1: the front end's fixed limits on one large function, each lifted and checked just past its old value.

Each case is a function graph built just past one old limit and verified by the native general driver (the pinned
seed, or a candidate compiler under C1).  Before release 0039 the driver declines it (exit 2):

- the CFG program's output view (ledger 0039-cfg-view-1g): the dominator sets take n * ceil(n / 64) words beside a
  fixed copy of the 8M-word input, and the 128 MiB view (16M words) held them up to about 22,000 blocks.  A chain of
  24,000 blocks needs about 17.4M words; the 1 GiB view holds about 85,000 blocks.
- the semantic index's block section (ledger 0039-index-section-region): each block's parameter and edge argument
  types, 1M words at word 23M.  It moves to words 29M-32M (3M words); the node stream grows to 4M words (20M-24M) and
  the facts end at 28M, where the globals begin.  12,500 blocks of 37 values need about 1.1M section words.
- the graph decoder's body view (ledger 0039-decoder-body-8m, ledger 0021 regenerated): the driver read a graph body
  into 4 MiB buffers.  They are 8 MiB; the decoder's own output (one word per body byte, 8M words less 4,096) is the
  bound after it.  20,000 blocks of 37 values make a body of about 4.2 MB.
- the edit engine's body region (ledgers 0039-edit-body-8m-a and -b): ``edit`` re-encodes a changed graph body into
  4M words at word 54.125M, directly below the new objects' preimages, and a larger body ran into them: the output
  store failed verification (``XAX.STRUCT.VALUE_TAG``).  The region is 8M + 64K words, the preimages start at
  62.1875M and keep their end (12,517,376 words, was 16M).  One constant of the 4.2 MB body is changed.

Python here is test scaffolding: it builds the input graph with the reference builder and runs the native driver.
The stores are written without the reference verifier, which is too slow on graphs of this size.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

from xax_compiler import Kind, Operation, bits_type, object_with_refs, write_store, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder
from xax_linux import linux_api

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B32 = bits_type(32)


def chain_store(blocks: int, values: int = 0) -> bytes:
    """A Linux program whose entry passes its three effects and ``values`` ``bits<32>`` values through ``blocks``
    blocks in a chain, then exits 7."""
    api = linux_api()
    state = (api.process_effect, api.filesystem_effect, api.memory_effect)
    graph = GraphBuilder()
    graph.track(*api.types, B32)
    entry = graph.block(*state)
    chain = [graph.block(*state, *(B32,) * values) for _ in range(blocks - 1)]
    entry.br(chain[0], *entry.params, *(entry.const(B32, k) for k in range(values)))
    for block, following in zip(chain, chain[1:]):
        block.br(following, *block.params)
    last = chain[-1]
    process, fs, memory = last.params[:3]
    status = last.const(B32, 7)
    process = last.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    last.ret(status, process, fs, memory)
    entry = graph.function(state, (B32, *state))
    target = x86_64_linux_exec_target()
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    available = {item.cid: item for item in (*graph.objects.values(), *api.types, entry, target, module, root)}
    reachable, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    return write_store(root.cid, tuple(reachable.values()))


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class FrontEndLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 900
        cls.directory = tempfile.mkdtemp()

    def assertVerifies(self, data: bytes):
        store, output = (os.path.join(self.directory, name) for name in ("store.xax", "out.bin"))
        Path(store).write_bytes(data)
        self.assertEqual(self.driver.verify(store, output), 0)

    def test_cfg_dominators_past_the_old_view(self):
        self.assertVerifies(chain_store(24_000))

    def test_block_section_past_the_old_region(self):
        self.assertVerifies(chain_store(12_500, 37))

    def test_graph_body_past_the_old_view(self):
        self.assertVerifies(chain_store(20_000, 37))

    def test_edit_of_a_body_past_the_old_region(self):
        store, empty, listing, selector, view, batch, edited, output = (
            os.path.join(self.directory, name) for name in ("big.xax", "empty", "list", "sel", "view", "batch", "edited.xax", "out"))
        Path(store).write_bytes(chain_store(20_000, 37))
        Path(empty).write_text("")
        self.assertEqual(self.driver.view(store, empty, listing), 0)
        root, function = Path(listing).read_text().splitlines()[:2]
        Path(selector).write_text(function.split()[0] + "\n")
        self.assertEqual(self.driver.view(store, selector, view), 0)
        node = next(line.split()[0] for line in Path(view).read_text().splitlines() if line.split()[1:3] == ["constant", "36"])
        Path(batch).write_text(f"{root}\n{function.split()[0]}\nconst {node} 35\n")
        self.assertEqual(self.driver.apply(store, batch, edited), 0)
        self.assertEqual(self.driver.verify(edited, output), 0)


if __name__ == "__main__":
    unittest.main()
