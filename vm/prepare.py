#!/usr/bin/env python3
"""Prepare a relocatable Apple Silicon QEMU with USB host support in one directory."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse


def checked(*args):
    return subprocess.check_output([str(arg) for arg in args], text=True)


def fetch(url, output=None, token=None):
    args = ["curl", "--fail", "--silent", "--show-error", "--location", "--retry", "2",
            "--connect-timeout", "15", "--proto", "=https", "--proto-redir", "=https"]
    if token:
        args += ["--header", "Authorization: Bearer " + token]
    if output:
        args += ["--output", str(output)]
    return checked(*args, url)


def compatible_bottle(formula):
    bottles = formula["bottle"]["stable"]["files"]
    versions = [(27, "golden_gate"), (26, "tahoe"), (15, "sequoia"),
                (14, "sonoma"), (13, "ventura"), (12, "monterey"), (11, "big_sur")]
    os_major = int(platform.mac_ver()[0].split(".")[0])
    for major, codename in versions:
        if os_major >= major and "arm64_" + codename in bottles:
            return bottles["arm64_" + codename], codename
    if "all" in bottles:
        return bottles["all"], "all"
    raise RuntimeError("No compatible arm64 bottle for " + formula["name"])


def download(formula_name, cache, pins):
    if not re.fullmatch(r"[a-z0-9][a-z0-9+@.-]*", formula_name):
        raise ValueError("Unexpected formula name: " + formula_name)
    if pins is None:
        metadata = json.loads(fetch("https://formulae.brew.sh/api/formula/" + formula_name + ".json"))
        bottle, platform_name = compatible_bottle(metadata)
        record = {"version": metadata["versions"]["stable"], "revision": metadata["revision"],
                  "platform": platform_name, "url": bottle["url"], "sha256": bottle["sha256"],
                  "license": metadata["license"]}
    else:
        record = pins[formula_name]
    sha, url = record["sha256"], record["url"]
    location = re.fullmatch(r"https://ghcr.io/v2/(homebrew/core/[a-z0-9/_.-]+)/blobs/sha256:([0-9a-f]{64})", url)
    if not location or location[2] != sha:
        raise ValueError("Unrecognized Homebrew container reference: " + url)
    archive = cache / (formula_name + ".tar.gz")
    previous = os.environ.get("QEMU_BOTTLE_CACHE")
    if previous and (Path(previous)/archive.name).is_file():
        shutil.copyfile(Path(previous)/archive.name, archive)
    else:
        query = urllib.parse.urlencode({"service": "ghcr.io", "scope": "repository:" + location[1] + ":pull"})
        token = json.loads(fetch("https://ghcr.io/token?" + query))["token"]
        print("Downloading " + formula_name, file=sys.stderr, flush=True)
        fetch(url, archive, token)
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for block in iter(lambda: source.read(1024*1024), b""):
            digest.update(block)
    if digest.hexdigest() != sha:
        raise ValueError("Bottle digest mismatch for " + formula_name)
    return record


def extract(archive, requests):
    # Normalize Homebrew's versioned path only inside the verified archive.
    # Write bytes to preselected private destinations, never extract tar paths.
    with tarfile.open(archive, "r:*") as package:
        by_path = {}
        for item in package.getmembers():
            path = PurePosixPath(item.name)
            if path.is_absolute() or ".." in path.parts or len(path.parts) < 3:
                continue
            rel = str(PurePosixPath(*path.parts[2:]))
            by_path[rel] = item
        for rel, dest in requests:
            item = by_path.get(rel)
            if item is None or not (item.isfile() or item.issym() or item.islnk()):
                raise ValueError(f"{rel} missing in {archive.name}")
            with package.extractfile(item) as src, dest.open("xb") as dst:
                shutil.copyfileobj(src, dst)
            dest.chmod(0o755)


def dependencies(path, is_library):
    lines = checked("otool", "-L", path).splitlines()[1:]
    if is_library:
        lines = lines[1:]  # LC_ID_DYLIB
    for line in lines:
        name = line.strip().split(" (compatibility version")[0]
        if name.startswith(("/usr/lib/", "/System/Library/")):
            continue
        match = re.fullmatch(r"(?:@@HOMEBREW_PREFIX@@|/opt/homebrew|/usr/local)/opt/([^/]+)/(lib/.+)", name)
        if not match:
            match = re.fullmatch(r"(?:@@HOMEBREW_CELLAR@@|(?:@@HOMEBREW_PREFIX@@|/opt/homebrew|/usr/local)/Cellar)/([^/]+)/[^/]+/(lib/.+)", name)
        if not match:
            raise ValueError(f"Unsupported install name in {path.name}: {name}")
        yield name, match[1], match[2]


def prepare(root):
    cache = root / "bottles"
    # The arm64 virt machine boots its kernel directly, without guest BIOS or
    # network option ROMs. Point QEMU at this empty private firmware directory.
    for directory in [cache, root/"bin", root/"lib", root/"share/qemu"]:
        directory.mkdir(parents=True)
    major = int(platform.mac_ver()[0].split(".")[0])
    lock = Path(__file__).parent / f"bottles-macos{major}.json"
    pins = json.loads(lock.read_text()) if lock.is_file() else None
    program = root / "bin/qemu-system-aarch64"
    pending = {"qemu": [("bin/qemu-system-aarch64", program)]}
    providers = {program: ("qemu", "bin/qemu-system-aarch64")}
    manifest, changes = {}, {}
    while pending:
        names = [name for name in pending if name not in manifest]
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda name: download(name, cache, pins), names))
        manifest.update(zip(names, results))
        next_pending = {}
        for owner, requests in pending.items():
            extract(cache / (owner + ".tar.gz"), requests)
            for _, path in requests:
                rewrites = []
                changes[path] = rewrites
                for name, formula, lib_path in dependencies(path, path != program):
                    basename = PurePosixPath(lib_path).name
                    dest = root / "lib" / basename
                    if dest in providers and providers[dest] != (formula, lib_path):
                        raise ValueError("Two bottles require different libraries named " + basename)
                    if dest not in providers:
                        providers[dest] = (formula, lib_path)
                        next_pending.setdefault(formula, []).append((lib_path, dest))
                    prefix = "@loader_path/" if path != program else "@executable_path/../lib/"
                    rewrites.extend(["-change", name, prefix + basename])
        pending = next_pending
    entitlements = root / "hypervisor.plist"
    entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
    for path, rewrites in changes.items():
        if path != program:
            rewrites += ["-id", "@loader_path/" + path.name]
        if rewrites:
            checked("install_name_tool", *rewrites, path)
        args = ["codesign", "--force", "--sign", "-"]
        if path == program:
            args += ["--entitlements", entitlements]
        checked(*args, path)
    (root/"bottles.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    wrapper = root/"qemu-system-aarch64"
    wrapper.write_text('#!/bin/sh\nset -eu\nhere=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec "$here/bin/qemu-system-aarch64" -L "$here/share/qemu" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


def usb_supported(binary):
    probe = subprocess.run([str(binary), "-device", "usb-host,help"], capture_output=True, text=True)
    return probe.returncode == 0 and "vendorid" in probe.stdout + probe.stderr


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 vm/prepare.py NEW_OUTPUT_DIRECTORY")
    installed = shutil.which("qemu-system-aarch64")
    if installed and usb_supported(installed):
        print(Path(installed).resolve())
        sys.exit(0)
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        sys.exit("Project-local bottles require an Apple Silicon Mac.")
    root = Path(sys.argv[1]).resolve()
    os.umask(0o077)
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        sys.exit("Choose an empty output directory; previous builds are preserved.")
    runtime = prepare(root)
    if not usb_supported(runtime):
        sys.exit("The prepared QEMU failed its USB host capability check.")
    print(runtime)
