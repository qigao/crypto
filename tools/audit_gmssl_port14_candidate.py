#!/usr/bin/env python3
"""Fail closed on any drift in the seven imported GmSSL port14 candidate blobs."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "59693dfdb4e6830df838edf9da109f855fd2ea24"
EXPECTED = {
    "providers/gmssl/candidates/port14/handshake-framing.cmake": "a29f6ade40e308c2f2b80d8b04596b31ca3435f6",
    "providers/gmssl/candidates/port14/tls13-handshake-reader.h": "1322420db5e84ce6bfe335d3dd3f4637f4482953",
    "providers/gmssl/candidates/port14/tls13-compat-ccs.h": "f424e036f5719368d884ae0ddbc1903b8c5a6f7a",
    "providers/gmssl/candidates/port14/tls13-hrr-padding.h": "4da4e56f6c612bac9be8dc8397b340ca973ed82d",
    "providers/gmssl/candidates/port14/tests/CMakeLists.txt": "4280528a450700a62dcc8d278f5648ff05eae3a3",
    "providers/gmssl/candidates/port14/tests/tls13-dummy-ccs-contract.c": "b8e4f540d2b334666b30dd809e9caf07287a0141",
    "providers/gmssl/candidates/port14/tests/tls13-dummy-ccs-interop.py": "60ee7ff30a4f0877f6950d2fd746d4bba1c33f0e",
}

def main() -> None:
    cmd = ["git", "-C", str(ROOT), "ls-tree", "-rz", "HEAD", "--",
           "providers/gmssl/candidates/port14"]
    raw = subprocess.check_output(cmd)
    objects: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        info, name = item.split(b"\t", 1)
        mode, kind, sha = info.decode("ascii").split()
        if mode != "100644" or kind != "blob":
            raise ValueError("candidate contains an unexpected nonregular git object")
        objects[name.decode("utf-8")] = sha
    if objects != EXPECTED:
        raise ValueError("port14 source changed: missing/extra/modified blobs\n"
                         f"expected={EXPECTED}\nactual={objects}")
    print(f"PASS: {len(EXPECTED)} exact Crypto-owned port14 candidate files from {SOURCE_SHA}")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print("FAIL Crypto port14 immutable handoff: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
