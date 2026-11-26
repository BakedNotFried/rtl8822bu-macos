"""Authenticate an Alpine APK v2 control signature and its SHA-256 data reference."""
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import zlib

HERE = Path(__file__).resolve().parent
REPOSITORY = "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/aarch64/"
KEY_SHA256 = "d11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d"
SIGNATURE = ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub"


def packages():
    return json.loads((HERE / "packages.lock.json").read_text())


def split_member(data):
    decoder = zlib.decompressobj(31)
    unpacked = decoder.decompress(data)
    if not decoder.eof or not decoder.unused_data:
        raise ValueError("Truncated Alpine package")
    size = len(data) - len(decoder.unused_data)
    return unpacked, data[:size], decoder.unused_data


def verify(name, record, package):
    if len(package) != record["size"]:
        raise ValueError(f"{name}: package size mismatch")
    if hashlib.sha256(package).hexdigest() != record["sha256"]:
        raise ValueError(f"{name}: package SHA-256 mismatch")
    key = HERE / "alpine-aarch64.rsa.pub"
    if hashlib.sha256(key.read_bytes()).hexdigest() != KEY_SHA256:
        raise ValueError("Alpine signing key mismatch")
    signature_tar, _, remaining = split_member(package)
    control_tar, control, data = split_member(remaining)
    if "Q1" + base64.b64encode(hashlib.sha1(control).digest()).decode() != record["control"]:
        raise ValueError(f"{name}: signed package index mismatch")
    with tarfile.open(fileobj=io.BytesIO(signature_tar)) as archive:
        signature = archive.extractfile(SIGNATURE).read()
    # Alpine v2 uses RSA/SHA-1 for this signature. The signed control stream
    # covers the SHA-256 of the compressed data, and we pin the full APK SHA-256.
    rd, wr = os.pipe()
    try:
        os.write(wr, signature)
        os.close(wr)
        subprocess.run(["/usr/bin/openssl", "dgst", "-sha1", "-verify", str(key),
                        "-signature", f"/dev/fd/{rd}"], pass_fds=(rd,), input=control,
                       check=True, stdout=subprocess.DEVNULL)
    finally:
        os.close(rd)
    with tarfile.open(fileobj=io.BytesIO(control_tar)) as archive:
        details = dict(line.split(" = ", 1) for line in
                       archive.extractfile(".PKGINFO").read().decode().splitlines() if " = " in line)
    if (details["pkgname"] != name or details["pkgver"] != record["version"] or
            details["arch"] not in ("aarch64", "noarch") or
            details["datahash"] != hashlib.sha256(data).hexdigest()):
        raise ValueError(f"{name}: package identity or payload does not match signature")
    return data


def get(name, record, cache):
    filename = f"{name}-{record['version']}.apk"
    path = cache / filename
    # The same cache may be shared by multiple fresh build directories.
    with (cache / (filename + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists():
            return verify(name, record, path.read_bytes())
        url = REPOSITORY + filename
        print(f"Fetching {filename}", flush=True)
        payload = subprocess.check_output(["/usr/bin/curl", "--fail", "--silent", "--show-error",
                                           "--location", "--proto", "=https", "--proto-redir",
                                           "=https", "--retry", "2", url])
        data = verify(name, record, payload)
        with path.open("xb") as output:
            output.write(payload)
        return data


if __name__ == "__main__":
    import concurrent.futures
    import sys
    cache = Path(sys.argv[1])
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    def fetch_one(item):
        name, record = item
        get(name, record, cache)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch_one, packages().items()))
