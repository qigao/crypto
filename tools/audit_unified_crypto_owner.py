#!/usr/bin/env python3
"""Audit ONE native GmSSL owner imported through two installed Crypto API views.

Requires final installed SDK binaries and native ELF/Mach-O/PE tools. CMake
target names alone, passing tests against two separate DSOs, or hidden symbols
in independently linked static libraries DO NOT qualify single ownership.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

TLS_EXPORTS = {
    "crypto_tls_abi_version", "crypto_tls_provider_create",
    "crypto_tls_provider_destroy", "crypto_tls_provider_session_count",
    "crypto_tls_session_create", "crypto_tls_session_handshake",
    "crypto_tls_session_send", "crypto_tls_session_receive",
    "crypto_tls_session_shutdown", "crypto_tls_session_cancel",
    "crypto_tls_session_destroy",
    "crypto_tls_extension_abi_version",
    "crypto_tls_get_features_v1_1",
    "crypto_tls_session_set_alpn_v1_1",
    "crypto_tls_session_get_info_v1_1",
}
SM3_EXPORTS = {
    "crypto_provider_abi_0_1_required",
    "crypto_provider_runtime_abi",
    "crypto_provider_sm3",
}
EXPECTED = TLS_EXPORTS | SM3_EXPORTS
ELF_VERSIONS = {"CRYPTO_TLS_1", "CRYPTO_TLS_EXT_1_1", "CRYPTO_PROVIDER_0_1"}


def cmd(*args: str) -> str:
    p = subprocess.run(args, capture_output=True, text=True, check=False)
    if p.returncode:
        raise RuntimeError(
            f"command {args!r} returned {p.returncode}: "
            + p.stdout[-1600:] + p.stderr[-1600:]
        )
    return p.stdout


def dumpbin() -> str:
    exe = shutil.which("dumpbin.exe") or shutil.which("dumpbin")
    if exe:
        return exe
    root = Path("C:/Program Files/Microsoft Visual Studio")
    candidates = sorted(
        root.glob("**/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"),
        reverse=True,
    )
    if not candidates:
        raise RuntimeError("Required MSVC dumpbin.exe unavailable; no audit fallback")
    return str(candidates[0])


def native_os() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    raise RuntimeError("Native binary audit unsupported on this platform")


def installed_binary(prefix: Path, osname: str) -> Path:
    if osname == "windows":
        path = prefix / "bin" / "crypto_tls.dll"
    elif osname == "macos":
        path = prefix / "lib" / "libcrypto_tls.dylib"
    else:
        path = prefix / "lib" / "libcrypto_tls.so"
    if not path.is_file():
        raise ValueError(f"missing one installed shared Crypto image: {path}")
    resolved = path.resolve(strict=True)
    if prefix.resolve() not in resolved.parents:
        raise ValueError(f"native Crypto shared file escapes SDK prefix: {resolved}")
    return resolved


def unique_file(root: Path, stem: str, osname: str, plugin: bool) -> Path:
    if plugin:
        suffix = ".dll" if osname == "windows" else ".so"
        name = ("" if osname == "windows" else "lib") + stem + suffix
    else:
        name = stem + (".exe" if osname == "windows" else "")
    files = [p for p in root.rglob(name) if p.is_file()]
    if len(files) != 1:
        raise ValueError(f"expected exactly one {name} in {root}, got {files}")
    return files[0].resolve()


def native_exports(image: Path, osname: str, pe_tool: str | None) -> set[str]:
    if osname == "linux":
        raw = cmd("nm", "-D", "--defined-only", str(image))
        names = {line.split()[-1].split("@")[0]
                 for line in raw.splitlines() if len(line.split()) >= 2}
        return names - ELF_VERSIONS
    if osname == "macos":
        raw = cmd("nm", "-gU", str(image))
        return {line.split()[-1].removeprefix("_")
                for line in raw.splitlines()
                if line.split() and line.split()[-1].startswith("_")}
    raw = cmd(pe_tool or dumpbin(), "/exports", str(image))
    names: set[str] = set()
    for line in raw.splitlines():
        m = re.match(r"^\s*\d+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+(\S+)", line)
        if m:
            names.add(m.group(1).split("=")[0])
    if not names:
        raise ValueError("no native PE exports")
    return names


def dynamic_dependencies(image: Path, osname: str, pe_tool: str | None) -> str:
    if osname == "linux":
        return cmd("readelf", "-d", str(image))
    if osname == "macos":
        return cmd("otool", "-L", str(image))
    return cmd(pe_tool or dumpbin(), "/dependents", str(image))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def audit(prefix: Path, build: Path) -> dict:
    prefix = prefix.resolve()
    build = build.resolve()
    osname = native_os()
    provider = installed_binary(prefix, osname)
    pe_tool = dumpbin() if osname == "windows" else None

    # Reject a second GmSSL-bearing native image in the same installed SDK.
    artifacts = [
        p.relative_to(prefix).as_posix()
        for p in prefix.rglob("*")
        if p.is_file() and (
            p.name.lower().startswith(("crypto_provider-", "libcrypto_provider",
                                       "gmssl.dll", "libgmssl."))
        )
    ]
    if artifacts:
        raise ValueError(f"second crypto/GmSSL binary owner installed: {artifacts}")

    exports = native_exports(provider, osname, pe_tool)
    if exports != EXPECTED:
        raise ValueError(
            f"expected only 18 SM3/TLS public exports, "
            f"missing={sorted(EXPECTED - exports)}, "
            f"unexpected={sorted(exports - EXPECTED)}"
        )
    if osname == "linux":
        soname = "libcrypto_tls.so.0"
        provider_dynamic = dynamic_dependencies(provider, osname, pe_tool)
        if f"[{soname}]" not in provider_dynamic:
            raise ValueError("missing reviewed ELF SONAME of the single Crypto image")
    elif osname == "macos":
        soname = "libcrypto_tls.0.dylib"
        install_name = cmd("otool", "-D", str(provider))
        if soname not in install_name:
            raise ValueError("single provider Mach-O install name mismatch")
    else:
        soname = "crypto_tls.dll"

    images = {
        "c11": unique_file(build, "crypto_owner_c11", osname, False),
        "cpp17": unique_file(build, "crypto_owner_cpp17", osname, False),
        "plugin_a": unique_file(build, "crypto_owner_plugin_a", osname, True),
        "plugin_b": unique_file(build, "crypto_owner_plugin_b", osname, True),
        "owner_process": unique_file(build, "crypto_owner_process", osname, False),
    }
    entries: dict[str, dict] = {}
    for label, path in {"shared_owner": provider, **images}.items():
        imported = dynamic_dependencies(path, osname, pe_tool)
        lower = imported.lower()
        if "gmssl.dll" in lower or "libgmssl." in lower:
            raise ValueError(f"{label} links a second private GmSSL binary")
        if "crypto_provider" in lower:
            raise ValueError(f"{label} imports a second Crypto Provider DSO")
        if label != "shared_owner":
            if lower.count(soname.lower()) != 1:
                raise ValueError(
                    f"{label} must import exact one Crypto native owner, "
                    f"expected {soname}, imports:\n{imported}"
                )
        entries[label] = {
            "sha256": sha256(path),
            "native_path": str(path),
            "imports_shared_crypto": label != "shared_owner",
        }

    return {
        "schema": 1,
        "classification": "DRAFT_ONE_SHARED_GMSSL_OWNER_SM3_AND_TLS_NOT_PRODUCTION",
        "platform": osname,
        "single_native_owner": soname,
        "physical_abi_export_count": len(exports),
        "exports": sorted(exports),
        "artifacts": entries,
        "ok": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", type=Path, required=True)
    ap.add_argument("--build-dir", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    opts = ap.parse_args()
    try:
        evidence = audit(opts.prefix, opts.build_dir)
    except (OSError, RuntimeError, ValueError) as ex:
        evidence = {"schema": 1, "ok": False, "reason": str(ex)}
    opts.report.parent.mkdir(parents=True, exist_ok=True)
    opts.report.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    if not evidence["ok"]:
        print("Crypto SM3/TLS single native owner: FAIL " + evidence["reason"],
              file=sys.stderr)
        return 1
    print(f"Crypto single shared owner: PASS ({evidence['platform']}, "
          f"{evidence['physical_abi_export_count']} native exports; "
          "C11/C++17 plus two independent native MODULEs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
