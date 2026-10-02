"""Build the host-side Android environment used by the device-free Android evidence (ADR-106).

Validation tooling only; nothing here is part of XAX code generation.  It downloads
pinned Google archives (SHA-256 checked) into ``--prefix`` (default ``/opt/android``) and
assembles a root filesystem for ``qemu-aarch64 -L <prefix>/root`` that holds Android 14's
own ``linker64``, bionic, ART (``dex2oat64``/``oatdump``), the framework boot classpath,
and the precompiled arm64 boot image:

    system image zip -> system.img (GPT) -> ``super`` (LP metadata) -> ``system`` (ext4)
      -> /system/{bin,lib64,framework}
      -> APEX/CAPEX payloads: runtime (bionic, linker), art, i18n, os.statsd

It also fetches the libxposed API 102.0.0 AAR from Maven Central and dexes it, so ART can
verify libxposed modules against the API they compile against.  Requires ``curl``,
``unzip``, ``debugfs`` (e2fsprogs), Java, and ``qemu-user-static``.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

REPOSITORY = "https://dl.google.com/android/repository/"
ARCHIVES = {
    "sys-img/android/arm64-v8a-34_r04.zip": "1447958a4c6747c44390ac5f5f4c894be6d1dfce93868a0385a95c5f0ae4c339",
    "android-ndk-r28c-linux.zip": "dfb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f",
    "build-tools_r36.1_linux.zip": "a7b5889e4a79fcf3b0976bef40d401f4240fb1eed891d9d91169da1111e11d78",
    "platform-35_r02.zip": "0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0",
}
LIBXPOSED_API = (
    "https://repo1.maven.org/maven2/io/github/libxposed/api/102.0.0/api-102.0.0.aar",
    "423484a6e1807e7a423c4b88fcd8176d104318259d91791877fed88fe91479d0",
)
APEXES = ("com.android.runtime", "com.android.art", "com.android.i18n", "com.android.os.statsd")
SECTOR = 512


def _fetch(url: str, sha256: str, path: Path) -> Path:
    if not path.exists():
        subprocess.run(["curl", "-sSfL", "-o", str(path), url], check=True)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != sha256:
        raise SystemExit(f"{path.name}: SHA-256 {digest} != pinned {sha256}")
    return path


def _super_partition(image: Path) -> tuple[int, int]:
    """Byte offset and size of the GPT partition named ``super``."""
    with image.open("rb") as handle:
        handle.seek(SECTOR)
        header = handle.read(92)
        entries_lba, count, size = struct.unpack_from("<QII", header, 72)
        handle.seek(entries_lba * SECTOR)
        for _ in range(count):
            entry = handle.read(size)
            first, last = struct.unpack_from("<QQ", entry, 32)
            if entry[56:128].decode("utf-16le").rstrip("\0") == "super":
                return first * SECTOR, (last - first + 1) * SECTOR
    raise SystemExit("no super partition")


def _lp_partition(image: Path, super_offset: int, name: str) -> tuple[int, int]:
    """Byte offset (in the image) and size of one logical partition, from LP metadata."""
    with image.open("rb") as handle:
        handle.seek(super_offset + 4096 + 2 * 4096)  # reserved, two geometry copies, then primary metadata
        header = handle.read(256)
        header_size, = struct.unpack_from("<I", header, 8)
        descriptors = [struct.unpack_from("<III", header, 80 + 12 * index) for index in range(4)]
        handle.seek(super_offset + 4096 + 2 * 4096 + header_size)
        tables = handle.read(1 << 20)
    (partitions, partition_count, partition_size), (extents, _extent_count, extent_size) = descriptors[:2]
    for index in range(partition_count):
        entry = tables[partitions + index * partition_size:][:partition_size]
        if entry[:36].rstrip(b"\0").decode() == name:
            _attributes, first_extent, extent_total, _group = struct.unpack_from("<IIII", entry, 36)
            if extent_total != 1:
                raise SystemExit(f"{name}: {extent_total} extents")
            sectors, _target_type, target, _source = struct.unpack_from("<QIQI", tables, extents + first_extent * extent_size)
            return super_offset + target * SECTOR, sectors * SECTOR
    raise SystemExit(f"no logical partition {name}")


def _debugfs(image: Path, command: str) -> None:
    subprocess.run(["debugfs", "-R", command, str(image)], check=True, capture_output=True)


def _extract_apex(system: Path, work: Path, root: Path, name: str) -> None:
    listing = subprocess.run(["debugfs", "-R", "ls /system/apex", str(system)], check=True, capture_output=True, text=True).stdout.split()
    file = next(item for item in listing if item in (f"{name}.apex", f"{name}.capex"))
    archive = work / file
    _debugfs(system, f"dump /system/apex/{file} {archive}")
    with zipfile.ZipFile(archive) as outer:
        if "original_apex" in outer.namelist():  # compressed APEX wraps the original
            (work / f"{name}.apex").write_bytes(outer.read("original_apex"))
            outer = zipfile.ZipFile(work / f"{name}.apex")
        (work / f"{name}.img").write_bytes(outer.read("apex_payload.img"))
    destination = root / "apex" / name
    destination.mkdir(parents=True, exist_ok=True)
    _debugfs(work / f"{name}.img", f"rdump / {destination}")


def _relativize_symlinks(root: Path) -> None:
    """Absolute symlinks in the image point into the device root; make them relative to ``root``."""
    for directory, names, files in os.walk(root):
        for name in (*names, *files):
            path = Path(directory) / name
            if path.is_symlink() and os.readlink(path).startswith("/"):
                target = root / os.readlink(path).lstrip("/")
                path.unlink()
                path.symlink_to(os.path.relpath(target, directory))


# Namespaces nativeloader asks for when ART runs (dalvikvm64).  On a device these come from
# /linkerconfig/ld.config.txt, generated at boot; every one here resolves through ``default``,
# so no library is ever loaded twice.
_NAMESPACES = ("system", "com_android_art", "com_android_runtime", "com_android_i18n", "com_android_os_statsd", "com_android_conscrypt", "com_android_tzdata")


def _write_runtime_configuration(root: Path) -> None:
    """Linker namespaces and public libraries that ART needs outside a booted device."""
    lines = [
        "# Host-validation linker configuration (a device generates this at boot).",
        *(f"dir.host = {directory}" for directory in (f"{root}/", "/apex/", "/system/", "/data/")),
        "[host]",
        "additional.namespaces = " + ",".join(_NAMESPACES),
        "namespace.default.isolated = false",
        "namespace.default.search.paths = " + ":".join(f"/apex/{name}/${{LIB}}" for name in APEXES) + ":/system/${LIB}",
    ]
    for name in _NAMESPACES:
        lines += [f"namespace.{name}.isolated = false", f"namespace.{name}.visible = true",
                  f"namespace.{name}.links = default", f"namespace.{name}.link.default.allow_all_shared_libs = true"]
    (root / "linkerconfig").mkdir(exist_ok=True)
    (root / "linkerconfig/ld.config.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Only bionic is public here; the framework's JNI libraries are not loaded by a bare dalvikvm.
    (root / "system/etc/public.libraries.txt").write_text("libc.so\nlibm.so\nlibdl.so\nliblog.so\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prefix", type=Path, default=Path("/opt/android"))
    prefix = parser.parse_args().prefix
    prefix.mkdir(parents=True, exist_ok=True)
    for relative, sha256 in ARCHIVES.items():
        archive = _fetch(REPOSITORY + relative, sha256, prefix / Path(relative).name)
        destination = {"arm64-v8a": "sysimg", "android-ndk": ".", "build-tools": "bt36", "platform": "platform"}[next(key for key in ("arm64-v8a", "android-ndk", "build-tools", "platform") if archive.name.startswith(key))]
        subprocess.run(["unzip", "-q", "-o", str(archive), "-d", str(prefix / destination)], check=True)

    image = prefix / "sysimg/arm64-v8a/system.img"
    super_offset, _super_size = _super_partition(image)
    offset, size = _lp_partition(image, super_offset, "system")
    system = prefix / "system_part.img"
    with image.open("rb") as source, system.open("wb") as out:
        source.seek(offset)
        out.write(source.read(size))

    root = prefix / "root"
    shutil.rmtree(root, ignore_errors=True)
    (root / "system").mkdir(parents=True)
    for directory in ("bin", "lib64", "framework", "etc"):
        _debugfs(system, f"rdump /system/{directory} {root / 'system'}")
    work = prefix / "apex-work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    for name in APEXES:
        _extract_apex(system, work, root, name)
    for directory in ("data/local/tmp", "data/dalvik-cache"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    _relativize_symlinks(root)
    _write_runtime_configuration(root)

    library = prefix / "libxposed"
    library.mkdir(exist_ok=True)
    aar = _fetch(*LIBXPOSED_API, library / "api-102.0.0.aar")
    (library / "classes.jar").write_bytes(zipfile.ZipFile(aar).read("classes.jar"))
    dex = library / "dex"
    dex.mkdir(exist_ok=True)
    build_tools = prefix / "bt36/android-16"
    subprocess.run([str(build_tools / "d8"), "--release", "--min-api", "28", "--lib", str(prefix / "platform/android-35/android.jar"),
                    "--output", str(dex), str(library / "classes.jar")], check=True, env={**os.environ, "JAVA_TOOL_OPTIONS": ""})
    with zipfile.ZipFile(library / "libxposed-api-102-dex.jar", "w") as out:
        out.write(dex / "classes.dex", "classes.dex")
    print(root)


if __name__ == "__main__":
    main()
