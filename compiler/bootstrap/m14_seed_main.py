"""Entry point embedded in the immutable M14 semantic-image seed archive."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from blake3 import blake3

from xax_selfhost import load_m14_program, m14_compile_own_generation


def main() -> int:
    parser = argparse.ArgumentParser(prog="xax-m14-seed")
    subparsers = parser.add_subparsers(dest="command", required=True)
    rebuild = subparsers.add_parser("rebuild")
    rebuild.add_argument("input")
    rebuild.add_argument("output")
    args = parser.parse_args()

    if args.command == "rebuild":
        source = Path(args.input).read_bytes()
        reader = load_m14_program(source)
        output = m14_compile_own_generation(reader)
        Path(args.output).write_bytes(output)
        print(
            json.dumps(
                {
                    "input_root": reader.root_cid.hex(),
                    "input_digest": blake3(source).hexdigest(),
                    "output_digest": blake3(output).hexdigest(),
                    "byte_identical": source == output,
                },
                sort_keys=True,
            )
        )
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
