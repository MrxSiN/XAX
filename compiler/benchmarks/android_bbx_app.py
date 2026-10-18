"""Build the BBX test Activity using XAX's public test signing fixture.

Run from compiler: python -m benchmarks.android_bbx_app module.bbx output-dir
The certificate is public test data and must never sign a production release.
"""
import sys
from pathlib import Path

from xax_apk_signing import sign_apk_v2
from xax_bbx_android import build_bbx_app
from xax_compiler import write_store


def main():
    from benchmarks.bench_android_apk import _signing_capability

    source, destination = map(Path, sys.argv[1:])
    app = build_bbx_app(source.read_bytes())
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in (
        ("libbbxdecision.so", app.library), ("classes.dex", app.dex),
        ("bbx-decision.apk", sign_apk_v2(app.unsigned_apk, _signing_capability())),
        ("native.xax", write_store(app.native_reader.root_cid, tuple(app.native_reader.objects()))),
        ("managed.xax", write_store(app.managed_reader.root_cid, tuple(app.managed_reader.objects()))),
    ):
        (destination / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
