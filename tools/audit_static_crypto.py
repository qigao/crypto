#!/usr/bin/env python3
"""Fail-closed audit: exactly one installed static Crypto archive, never a split owner."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

MANDATORY = (
    "crypto_provider_sm3",
    "crypto_tls_session_handshake",
    "crypto_tls_session_export_v1_2",
    "crypto_tls_cipher_bio_create",
    "salts_crypto_sha256",
    "salts_crypto_ed448_sign",
    "salts_crypto_ed448_verify",
    "salts_crypto_random_bytes",
    "salts_crypto_libecc_get_random",
    "sha256_init", "sha256_update", "sha256_finish",
)
FORBIDDEN = ("get_unsafe_random", "salts_crypto_libecc_salts_crypto_libecc_get_random")

def inspect(prefix: Path) -> dict:
    prefix = prefix.resolve(strict=True)
    lib = prefix / "lib"
    expected_name = "salts_crypto.lib" if sys.platform == "win32" else "libsalts_crypto.a"
    candidate = prefix / ("lib" if sys.platform != "win32" else "lib") / expected_name
    if not candidate.is_file():
        raise ValueError("canonical static archive missing: " + str(candidate))
    archives = sorted(p for p in prefix.rglob("*") if p.is_file()
                      and p.suffix.lower() in (".a", ".lib", ".dll", ".dylib", ".so"))
    if archives != [candidate]:
        raise ValueError("unexpected native crypto binaries: " +
                         ", ".join(str(p.relative_to(prefix)) for p in archives))
    for p in prefix.rglob("*"):
        if p.is_file() and re.search(r"\.so\.[0-9]+", p.name):
            raise ValueError("forbidden versioned shared library: " + str(p))
    cfg = lib / "cmake" / "Crypto" / "CryptoTargets.cmake"
    if not cfg.is_file():
        raise ValueError("missing installed CryptoTargets.cmake")
    value = cfg.read_text(encoding="utf-8")
    if not re.search(r"add_library\(Salts::Crypto STATIC IMPORTED\)", value):
        raise ValueError("installed Salts::Crypto is not a single static imported target")
    if re.search(r"\b(?:Salts::TLS|Salts::TLSHost|Salts::TLSCipherBIO|"
                 r"Salts::CryptoProvider|Crypto::|SaltsCrypto::)\w*", value):
        raise ValueError("split or alternate Crypto target in installed export")
    if "GmSSL::" in value or "PrivateGmSSL" in value:
        raise ValueError("installed static archive still links a private GmSSL target")
    report = {
        "ok": True,
        "archive": str(candidate.relative_to(prefix)),
        "source": "qigao/crypto",
        "target": "Salts::Crypto",
        "other_native_binaries": 0,
        "symbols_checked": False,
    }
    if sys.platform == "win32":
        # PE archive linkage is independently proven by the installed C11/C++17
        # tests. Do not pretend dumpbin's LINKERMEMBER display proves cardinality.
        return report
    cmd = ["nm", "-gU" if sys.platform == "darwin" else "-g",
           str(candidate)]
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if p.returncode != 0:
        raise ValueError("native archive nm failed: " + p.stderr[-3000:])
    symbols: Counter[str] = Counter()
    for line in p.stdout.splitlines():
        m = re.match(r"^\s*(?:[0-9a-fA-F]+\s+)?([A-TV-Z])\s+(\S+)\s*$", line)
        if not m or m.group(1) not in ("T", "D", "B", "R", "S", "C"):
            continue
        name = m.group(2)
        if sys.platform == "darwin":
            name = name.removeprefix("_")
        symbols[name] += 1
    absent = [s for s in MANDATORY if symbols[s] != 1]
    if absent:
        raise ValueError("mandatory Crypto symbol has nonunique definition: " +
                         str({s: symbols[s] for s in absent}))
    forbidden = [s for s in FORBIDDEN if symbols[s]]
    if forbidden:
        raise ValueError("obsolete or unsafe RNG symbol still present: " + str(forbidden))
    report["symbols_checked"] = True
    report["unique_symbols"] = list(MANDATORY)
    report["symbol_count"] = len(symbols)
    return report

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--prefix", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    try:
        result = inspect(args.prefix)
    except (OSError, ValueError) as exc:
        result = {"ok": False, "reason": str(exc)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Crypto static single archive: " + ("PASS" if result["ok"] else "FAIL " + result["reason"]))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
