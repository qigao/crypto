#!/usr/bin/env python3
"""Stage Crypto-owned, test-only GmSSL TLS1.2 mTLS source correction.

The pinned vcpkg-cache port 3.2.0#14 is copied into an ephemeral per-run
overlay. This script never mutates the registry, installed stable GmSSL,
production CNet or any checked-in upstream tree.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve()
REPOSITORY = HERE.parents[2]
PATCH_SOURCE = (
    REPOSITORY / "vendor" / "gmssl-extensions" /
    "patches" / "tls12-empty-authorities.cmake"
)
PATCH_NAME = PATCH_SOURCE.name
ANCHOR = 'include("${CMAKE_CURRENT_LIST_DIR}/tls12-rsa-mtls.cmake")'
EXTRA = 'include("${CMAKE_CURRENT_LIST_DIR}/' + PATCH_NAME + '")'


def stage(port: Path) -> None:
    portfile = port / "portfile.cmake"
    manifest = port / "vcpkg.json"
    if not (portfile.is_file() and manifest.is_file() and PATCH_SOURCE.is_file()):
        raise ValueError("missing exact pinned GmSSL port or Crypto source patch")
    metadata = json.loads(manifest.read_text(encoding="utf-8"))
    if metadata.get("name") != "gmssl" or metadata.get("version") != "3.2.0" or (
        metadata.get("port-version") != 14
    ):
        raise ValueError("expected only unmodified pinned GmSSL 3.2.0#14")
    original = portfile.read_text(encoding="utf-8")
    if original.count(ANCHOR) != 1 or EXTRA in original:
        raise ValueError("GmSSL mTLS adaptation anchor must occur exactly once")
    destination = port / PATCH_NAME
    if destination.exists():
        raise ValueError("refusing to overwrite existing GmSSL source patch")
    shutil.copyfile(PATCH_SOURCE, destination)
    portfile.write_text(original.replace(ANCHOR, ANCHOR + "\n" + EXTRA),
                        encoding="utf-8")
    print("PASS: Crypto-owned, test-only RFC5246 mTLS patch staged after pinned GmSSL #14")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: stage_mtls_gmssl_overlay.py <private overlay gmssl port>")
    try:
        stage(Path(sys.argv[1]).resolve(strict=True))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit("FAIL: M5 GmSSL source staging: " + str(exc)) from None
