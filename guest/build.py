#!/usr/bin/env python3
"""Build an isolated arm64 Linux kernel and newc initramfs without a Linux host."""
import gzip
import io
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import tarfile

sys.dont_write_bytecode = True
from fetch import HERE, get, packages


class Files:
    """Store guest paths in memory; archive paths never touch the macOS filesystem."""

    def __init__(self):
        self.entries = {}
        self.hardlinks = {}

    def add(self, path, mode, data=b"", device=(0, 0)):
        if not path or path.startswith("/") or ".." in PurePosixPath(path).parts:
            raise ValueError(f"Unsafe guest path: {path}")
        parent = str(PurePosixPath(path).parent)
        if parent != "." and parent not in self.entries:
            self.add(parent, stat.S_IFDIR | 0o755)
        self.entries[path] = (mode, data, device)

    def copy_member(self, tar, item):
        path = item.name
        if item.isdir():
            self.add(path, stat.S_IFDIR | item.mode)
        elif item.isreg():
            self.add(path, stat.S_IFREG | item.mode, tar.extractfile(item).read())
        elif item.issym():
            self.add(path, stat.S_IFLNK | 0o777, item.linkname.encode())
        elif item.islnk():
            self.hardlinks[path] = item.linkname
        else:
            raise ValueError(f"Unexpected guest package entry: {path}")

    def write_archive(self, destination):
        for path, target in self.hardlinks.items():
            self.add(path, *self.entries[target])
        with destination.open("xb") as out, gzip.GzipFile(
                fileobj=out, mode="wb", filename="", mtime=0, compresslevel=4) as archive:
            # Emit directories before their contents; modes/devices are guest metadata.
            ordered = sorted(self.entries.items())
            ordered.append(("TRAILER!!!", (0, b"", (0, 0))))
            for ino, (path, (mode, data, device)) in enumerate(ordered, 1):
                name = path.encode() + b"\0"
                fields = (ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0,
                          len(data), 0, 0, *device, len(name), 0)
                header = b"070701" + b"".join(f"{n:08x}".encode() for n in fields)
                archive.write(header + name + b"\0" * (-(len(header) + len(name)) % 4))
                archive.write(data)
                archive.write(b"\0" * (-len(data) % 4))


def kernel_image(data):
    if data[56:60] == b"ARMd":
        return data
    # Linux EFI zboot header describes the compressed Image (offset and size at 8).
    if data[4:8] != b"zimg" or data[24:28] != b"gzip":
        raise ValueError("Unsupported arm64 kernel container")
    offset, length = struct.unpack_from("<II", data, 8)
    if not offset or not length or length > len(data) - offset:
        raise ValueError("Invalid EFI zboot image bounds")
    image = gzip.decompress(data[offset:offset+length])
    if image[56:60] != b"ARMd":
        raise ValueError("Missing arm64 Image header")
    return image


def module_list(dep_text):
    deps = {}
    paths = {}
    for line in dep_text.splitlines():
        path, needed = line.split(":", 1)
        deps[path] = needed.split()
        name = path.rsplit("/", 1)[-1].split(".", 1)[0].replace("-", "_")
        paths[name] = path
    # AF_PACKET and 802.11 software crypto need runtime modules beyond rtw88's
    # direct ELF dependencies. AES/ECB and the PCI host bridge are kernel built-ins.
    roots = ("virtio_pci", "virtio_mmio", "virtio_console", "xhci_pci",
             "af_packet", "ctr", "cmac", "ccm", "gcm", "rtw88_8822bu")
    ordered = {}
    def include(path):
        if path in ordered:
            return
        for child in deps[path]:
            include(child)
        ordered[path] = None
    for name in roots:
        include(paths[name])
    return list(ordered)


def add_kernel(files, package):
    with tarfile.open(fileobj=io.BytesIO(package), mode="r|gz") as tar:
        modules = []
        image = None
        for item in tar:
            if item.name == "boot/vmlinuz-lts":
                image = kernel_image(tar.extractfile(item).read())
            elif item.name.endswith("/modules.dep"):
                prefix = item.name.rsplit("/", 1)[0]
                modules = [prefix + "/" + p for p in module_list(tar.extractfile(item).read().decode())]
    if not image or not modules:
        raise ValueError("Kernel image or module dependency list missing")
    with tarfile.open(fileobj=io.BytesIO(package), mode="r|gz") as tar:
        selected = set(modules)
        for item in tar:
            if item.name in selected:
                if not item.name.endswith(".ko.gz"):
                    raise ValueError("Unexpected module format")
                files.add(item.name[:-3], stat.S_IFREG | 0o644, gzip.decompress(tar.extractfile(item).read()))
                selected.remove(item.name)
        if selected:
            raise ValueError(f"Required modules missing: {sorted(selected)}")
    files.add("etc/station-modules", stat.S_IFREG | 0o644,
              "".join("/" + path[:-3] + "\n" for path in modules).encode())
    return image


def build(destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("Image", "initramfs.gz"):
        if (destination / name).exists():
            raise ValueError(f"{destination/name} exists; use a fresh output directory")
    cache = Path(os.getenv("STATION_APK_CACHE", HERE / "build" / "cache"))
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = Files()
    image = None
    for name, record in packages().items():
        data = get(name, record, cache)
        if name == "linux-lts":
            image = add_kernel(files, data)
            continue
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as tar:
            for item in tar:
                if name == "linux-firmware-rtw88" and item.name != "lib/firmware/rtw88/rtw8822b_fw.bin.zst":
                    continue
                files.copy_member(tar, item)
    for directory in ("dev", "proc", "sys", "run", "tmp", "usr/local/sbin"):
        files.add(directory, stat.S_IFDIR | (0o1777 if directory == "tmp" else 0o755))
    for applet in ("bin/sh", "bin/mount", "bin/sleep", "sbin/insmod", "sbin/poweroff"):
        files.add(applet, stat.S_IFLNK | 0o777, b"/bin/busybox")
    files.add("dev/console", stat.S_IFCHR | 0o600, device=(5, 1))
    files.add("dev/null", stat.S_IFCHR | 0o666, device=(1, 3))
    for source, path, perm in (
        ("init", "init", 0o755), ("station-guest", "usr/local/sbin/station-guest", 0o755),
        ("LICENCE.rtlwifi_firmware.txt", "usr/share/licenses/rtw88/LICENCE.rtlwifi_firmware.txt", 0o644),
        ("packages.lock.json", "usr/share/station/packages.lock.json", 0o644)):
        files.add(path, stat.S_IFREG | perm, (HERE/source).read_bytes())
    for path in ("lib/ld-musl-aarch64.so.1", "usr/bin/python3", "sbin/ip", "sbin/wpa_supplicant",
                 "sbin/wpa_cli", "usr/sbin/iw", "lib/firmware/rtw88/rtw8822b_fw.bin.zst",
                 "lib/firmware/regulatory.db", "lib/firmware/regulatory.db.p7s"):
        if path not in files.entries:
            raise ValueError(f"Guest runtime file missing: {path}")
    files.write_archive(destination / "initramfs.gz")
    with (destination / "Image").open("xb") as out:
        out.write(image)
    print(f"Guest image and initramfs ready in {destination}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 guest/build.py OUTPUT_DIRECTORY")
    build(Path(sys.argv[1]).resolve())
