#!/usr/bin/env python3
"""Fail-closed install of the only approved qigao/vcpkg-cache gmssl port.

Consumes vcpkg-cache's OVERLAY_PORTS, not an upstream GmSSL source checkout.
Never downloads/reconstructs GmSSL in qigao/crypto.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

EXPECTED_BLOBS = {
    "portfile.cmake": "196cb2109da104002463cca3849f4e03fd469fb6",
    "vcpkg.json": "b94a504d1a9b2e0b04c052a512a55e29525d11f0",
    "GmSSLConfig.cmake": "6539349471a849b4d613cbb9b1f05cd6ece313d1",
}
EXPECTED_VERSION = "3.2.0"
EXPECTED_PORT_VERSION = 14


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii") + data
    ).hexdigest()


def port_root() -> Path:
    entries = os.environ.get("VCPKG_OVERLAY_PORTS", "").split(os.pathsep)
    # vcpkg accepts platform-native path separators; require one explicit
    # qigao overlay, not a silent public registry fallback.
    for item in entries:
        root = Path(item) / "gmssl"
        if root.is_dir():
            return root
    raise RuntimeError("No qigao/vcpkg-cache gmssl overlay port configured")


def check_port() -> Path:
    port = port_root()
    for filename, sha in EXPECTED_BLOBS.items():
        path = port / filename
        if not path.is_file() or git_blob_sha(path.read_bytes()) != sha:
            raise RuntimeError("Untrusted/changed gmssl port: " + str(path))
    manifest = json.loads((port / "vcpkg.json").read_text(encoding="utf-8"))
    if (manifest.get("name"), manifest.get("version"),
            manifest.get("port-version")) != (
                "gmssl", EXPECTED_VERSION, EXPECTED_PORT_VERSION):
        raise RuntimeError("Incorrect qigao/vcpkg-cache gmssl 3.2.0#14")
    return port


def target_triplet(value: str) -> str:
    if value == "linux-x64":
        return "x64-linux"
    if value == "macos":
        return "arm64-osx" if os.environ.get("RUNNER_ARCH") == "ARM64" else "x64-osx"
    if value == "windows-x64":
        triplet = os.environ.get("QIGAO_VCPKG_WINDOWS_TRIPLET", "")
        if not triplet:
            raise RuntimeError("Missing vcpkg-cache Windows triplet")
        return triplet
    if value == "android-arm64":
        return "arm64-android"
    if value == "ios-arm64":
        return "arm64-ios"
    raise RuntimeError("Unsupported Crypto GmSSL platform: " + value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=(
        "linux-x64", "macos", "windows-x64", "android-arm64", "ios-arm64"))
    args = parser.parse_args()
    port = check_port()
    repo = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    vcpkg_root = Path(os.environ["VCPKG_ROOT"])
    triplet = target_triplet(args.target)
    executable = vcpkg_root / ("vcpkg.exe" if os.name == "nt" else "vcpkg")
    if not executable.is_file():
        raise RuntimeError("Canonical vcpkg executable missing: " + str(executable))
    prefix = repo / "vcpkg_installed" / triplet
    cmd = [str(executable), "install",
           "--x-manifest-root=" + str(repo),
           "--x-install-root=" + str(repo / "vcpkg_installed"),
           "--triplet=" + triplet]
    subprocess.run(cmd, check=True)
    for path in (
        prefix / "share/gmssl/GmSSLConfig.cmake",
        prefix / "include/gmssl/tls.h",
        prefix / "include/gmssl/sm3.h",
        prefix / "lib" / ("gmssl.lib" if os.name == "nt" else "libgmssl.a"),
    ):
        if not path.is_file():
            raise RuntimeError("Incomplete installed GmSSL vcpkg SDK: " + str(path))
    print("VERIFIED qigao/vcpkg-cache gmssl 3.2.0#14", port, triplet, prefix)
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as f:
        f.write("CRYPTO_GMSSL_ROOT=" + str(prefix) + "\n")
        f.write("CRYPTO_GMSSL_TRIPLET=" + triplet + "\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as e:
        print("ERROR: GmSSL vcpkg installation failed:", e, file=sys.stderr)
        sys.exit(1)
