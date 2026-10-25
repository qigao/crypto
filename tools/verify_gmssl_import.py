#!/usr/bin/env python3
"""Fail-closed GmSSL 3.2.0#13 source import verification.

The imported source tree and original vcpkg-cache handoff tarball MUST be
byte-for-byte identical to their recorded original Git blobs. This tool
does not compile GmSSL or authorize any Crypto API / CNet cutover.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "providers/gmssl"
MANIFEST = f"{ORIGIN}/provenance/ownership-manifest.json"
ORDER = f"{ORIGIN}/provenance/patch-order.json"
LICENSE = f"{ORIGIN}/LICENSE"
README = f"{ORIGIN}/README.md"
EXPECTED_ARCHIVE_SHA256 = (
    "586bbee98e7a6ba83ab13549d369d01fc341788ab3c53be5372d2bc063da4601"
)
EXPECTED_BLOBS = {
    MANIFEST: "55c282332aaddf3b555ba10dba7100ec839fe51a",
    LICENSE: "d9a10c0d8e868ebf8da0b3dc95bb0be634c34bfe",
    README: "77c49542ebfc1b5713eeacf016f778ad0460b673",
}


def git(*args: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), *args], stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as exc:
        raise ValueError(
            f"git {' '.join(args)} failed: {exc.stderr.decode(errors='replace')}"
        ) from exc


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def safe_path(s: str) -> None:
    p = PurePosixPath(s)
    if not s or s.startswith("/") or "\\" in s or "//" in s or ".." in p.parts or p.as_posix() != s:
        raise ValueError(f"unsafe or noncanonical import path: {s}")


def classify(path: str) -> tuple[str, str]:
    safe_path(path)
    if path in ("portfile.cmake", "vcpkg.json", "GmSSLConfig.cmake"):
        return "vcpkg-packaging", f"vcpkg-cache/ports/gmssl/{path}"
    if path.startswith("tests/"):
        return "provider-conformance", f"{ORIGIN}/tests/{path[6:]}"
    if path.endswith((".c", ".h")):
        return "provider-source-backport", f"{ORIGIN}/patches/{path}"
    if path.endswith((".cmake", ".patch")):
        return "upstream-source-patch", f"{ORIGIN}/patches/{path}"
    raise ValueError(f"unclassified source in frozen vcpkg port: {path}")


def tree_blobs() -> dict[str, str]:
    raw = git(
        "ls-tree", "-r", "-z", "HEAD", "--",
        f"{ORIGIN}/patches", f"{ORIGIN}/tests",
    )
    entries: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        header, path_bytes = record.split(b"\t", 1)
        mode, kind, sha = header.decode().split()
        path = path_bytes.decode("utf-8")
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError(f"nonregular imported source object: {path}")
        safe_path(path)
        if path in entries:
            raise ValueError(f"duplicate source path: {path}")
        entries[path] = sha
    return entries


def git_content(path: str) -> bytes:
    safe_path(path)
    return git("show", f"HEAD:{path}")


def verify() -> tuple[dict, dict[str, bytes]]:
    for path, expected in EXPECTED_BLOBS.items():
        data = git_content(path)
        if git_blob_sha(data) != expected:
            raise ValueError(f"immutable upstream provenance changed: {path}")

    manifest = json.loads(git_content(MANIFEST))
    source = manifest["source"]
    if source["repository"] != "qigao/vcpkg-cache":
        raise ValueError("unexpected provenance source repo")
    if (source["version"], source["port_version"]) != ("3.2.0", 13):
        raise ValueError("frozen GmSSL 3.2.0#13 version changed")
    if source["port_git_tree"] != "8e8fda20b723803adc53613f6f608736238ac97d":
        raise ValueError("frozen vcpkg registry port tree changed")
    if source["upstream_commit"] != "7c9f02904ef33e59c87b4f16621cc8fd434e7579":
        raise ValueError("upstream GmSSL Git pin changed")
    if source["upstream_license_git_blob_sha"] != EXPECTED_BLOBS[LICENSE]:
        raise ValueError("upstream Apache-2.0 license identity mismatch")
    if manifest["schema_version"] != 1 or len(manifest["files"]) != 95:
        raise ValueError("incomplete source manifest")

    trees = tree_blobs()
    payload: dict[str, bytes] = {}
    expected_paths: set[str] = set()
    counts: dict[str, int] = {}
    for row in manifest["files"]:
        path = row["path"]
        group, target = classify(path)
        if row["owner_group"] != group or row["target"] != target:
            raise ValueError(f"incorrect original source grouping: {path}")
        counts[group] = counts.get(group, 0) + 1
        if group == "vcpkg-packaging":
            if target in trees:
                raise ValueError(f"vcpkg packaging unexpectedly imported: {target}")
            continue
        if target in expected_paths:
            raise ValueError(f"duplicate source import mapping: {target}")
        expected_paths.add(target)
        if trees.get(target) != row["git_blob_sha"]:
            raise ValueError(f"Git source blob identity drift: {target}")
        content = git_content(target)
        if git_blob_sha(content) != row["git_blob_sha"]:
            raise ValueError(f"source content changed: {target}")
        payload[target] = content
    if set(trees) != expected_paths:
        extra = sorted(set(trees) - expected_paths)
        missing = sorted(expected_paths - set(trees))
        raise ValueError(f"unapproved Crypto sources: extra={extra}, missing={missing}")
    if counts != {
        "vcpkg-packaging": 3,
        "upstream-source-patch": 40,
        "provider-source-backport": 13,
        "provider-conformance": 39,
    } or counts != manifest["counts"]:
        raise ValueError(f"unexpected GmSSL source class counts: {counts}")

    order = json.loads(git_content(ORDER))
    original_scripts = {
        row["target"] for row in manifest["files"]
        if row["owner_group"] == "upstream-source-patch"
    }
    scripts = (
        [order["first_git_apply_patch"]] +
        list(order["ordered_cmake_source_adaptations"])
    )
    if (
        order["schema_version"] != 1
        or order["source"]["port_git_tree"] != source["port_git_tree"]
        or order["source"]["portfile_blob_sha"]
            != next(row["git_blob_sha"] for row in manifest["files"]
                    if row["path"] == "portfile.cmake")
        or len(scripts) != 40
        or len(set(scripts)) != 40
        or set(scripts) != original_scripts
    ):
        raise ValueError("GmSSL source patch ordering or coverage differs from port")
    payload[LICENSE] = git_content(LICENSE)
    payload[README] = git_content(README)
    payload[MANIFEST] = git_content(MANIFEST)
    if len(payload) != 95:
        raise ValueError("expected 92 provider payloads and 3 metadata files")
    print(
        f"PASS: {len(trees)} identical provider source/test Git blobs, "
        "vcpkg port 3.2.0#13 unchanged, 40 ordered patches, Apache-2.0 license"
    )
    return manifest, payload


def deterministic_tar(entries: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(entries):
            safe_path(path)
            content = entries[path]
            info = tarfile.TarInfo(path)
            info.size = len(content)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode="wb", filename="", mtime=0) as gz:
        gz.write(raw.getvalue())
    return result.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    manifest, payload = verify()
    archive = deterministic_tar(payload)
    actual = hashlib.sha256(archive).hexdigest()
    if actual != EXPECTED_ARCHIVE_SHA256:
        raise ValueError(
            f"migrated source tarball fingerprint differs: {actual}"
        )
    if args.archive is not None:
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        args.archive.write_bytes(archive)
    receipt = {
        "schema": 1,
        "qualification": "SOURCE_IMPORT_IDENTICAL_NOT_PROVIDER_BUILD_OR_RELEASE",
        "source_repository": "qigao/vcpkg-cache",
        "destination_repository": "qigao/crypto",
        "port_version": "3.2.0#13",
        "vcpkg_port_git_tree": manifest["source"]["port_git_tree"],
        "imported_source_files": 92,
        "excluded_packaging_files": 3,
        "archive_entries": 95,
        "archive_sha256": actual,
        "patched_gmssl_build_qualified": False,
    }
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"PASS: exact original handoff archive SHA-256 {actual}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL Crypto GmSSL source provenance: {exc}", file=sys.stderr)
        sys.exit(1)
