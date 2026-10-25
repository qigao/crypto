#!/usr/bin/env python3
"""Native single-owner and symbol leakage audit for pre-stable Crypto ABI 0.1.

Runs on the *installed, possibly relocated* SDK and independent clients.
Fail closed for missing nm/readelf/otool/dumpbin, non-versioned names, missing
Core imports or any exported original GmSSL symbol.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

EXPECTED = {
    "crypto_provider_abi_0_1_required",
    "crypto_provider_runtime_abi",
    "crypto_provider_sm3",
}


def command(*args: str) -> str:
    completed = subprocess.run(
        list(args), capture_output=True, text=True, check=False
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}) {args}: "
            + completed.stdout[-1600:] + completed.stderr[-1600:]
        )
    return completed.stdout


def dumpbin() -> str:
    located = shutil.which("dumpbin.exe") or shutil.which("dumpbin")
    if located:
        return located
    # Windows GitHub Actions bash need not have an activated VS Developer
    # Command Prompt even when the MSVC native tools are installed.
    root = Path("C:/Program Files/Microsoft Visual Studio")
    paths = sorted(
        root.glob("**/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"),
        reverse=True,
    )
    if not paths:
        raise FileNotFoundError("Required dumpbin.exe not found")
    return str(paths[0])


def find_bin(folder: Path, stem: str, osname: str, executable: bool) -> Path:
    if osname == "windows":
        basename = stem + (".exe" if executable else ".dll")
    else:
        # CMake MODULE libraries use .so on Darwin too (SHARED uses .dylib).
        basename = stem if executable else f"lib{stem}.so"
    paths = [p for p in folder.rglob(basename) if p.is_file()]
    if len(paths) != 1:
        raise ValueError(
            f"expected exactly one {basename} in {folder}, got {paths}"
        )
    return paths[0]


def exports(image: Path, osname: str, dumper: str | None) -> set[str]:
    if osname == "linux":
        output = command("nm", "-D", "--defined-only", str(image))
        names = set()
        for line in output.splitlines():
            fields = line.strip().split()
            if len(fields) < 2:
                continue
            name = fields[-1].split("@")[0]
            if name:
                names.add(name)
        return names - {"CRYPTO_PROVIDER_0_1"}
    if osname == "darwin":
        output = command("nm", "-gU", str(image))
        return {
            line.split()[-1].removeprefix("_")
            for line in output.splitlines()
            if line.split() and line.split()[-1].startswith("_")
        }
    output = command(dumper or dumpbin(), "/exports", str(image))
    names = set()
    for line in output.splitlines():
        match = re.match(
            r"^\s*\d+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+(\S+)", line
        )
        if match:
            names.add(match.group(1).split("=")[0])
    if not names:
        raise ValueError(f"no PE exported functions found: {image}")
    return names


def imports(image: Path, osname: str, dumper: str | None) -> str:
    if osname == "linux":
        return command("readelf", "-d", str(image))
    if osname == "darwin":
        return command("otool", "-L", str(image))
    return command(dumper or dumpbin(), "/dependents", str(image))


def exact_binary_identity(image: Path, osname: str) -> str:
    if osname == "windows":
        if image.name.lower() != "crypto_provider-0.1.dll":
            raise ValueError(f"unversioned Windows provider DLL: {image}")
        return image.name
    if osname == "linux":
        desc = command("readelf", "-d", str(image))
        token = "libcrypto_provider.so.0.1"
        if not re.search(r"\(SONAME\)[^\n]*\[libcrypto_provider[.]so[.]0[.]1\]", desc):
            raise ValueError("missing exact ELF 0.1 SONAME")
        return token
    text = command("otool", "-D", str(image))
    if not re.search(r"(?:@rpath/)?libcrypto_provider[.]0[.]1[.]dylib", text):
        raise ValueError("missing exact Mach-O 0.1 install-name")
    return "libcrypto_provider.0.1.dylib"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(args: argparse.Namespace) -> dict:
    osname = ("windows" if sys.platform == "win32" else
              "darwin" if sys.platform == "darwin" else "linux")
    prefix, build = args.prefix.resolve(), args.build_dir.resolve()
    dll = ("bin/crypto_provider-0.1.dll" if osname == "windows" else
           "lib/libcrypto_provider.0.1.0.dylib" if osname == "darwin"
           else "lib/libcrypto_provider.so.0.1.0")
    provider = prefix / dll
    if not provider.is_file():
        raise ValueError(f"installed shared Crypto provider missing: {provider}")
    resources = {
        "provider": provider,
        "consumer_c11": find_bin(build, "crypto_consumer_c11", osname, True),
        "consumer_cpp17": find_bin(build, "crypto_consumer_cpp17", osname, True),
        "module_a": find_bin(build, "crypto_probe_a", osname, False),
        "module_b": find_bin(build, "crypto_probe_b", osname, False),
        "consumer_modules": find_bin(build, "crypto_owner_consumer", osname, True),
    }
    dumper = dumpbin() if osname == "windows" else None
    exported = exports(provider, osname, dumper)
    if exported != EXPECTED:
        raise ValueError(
            f"Crypto Provider symbol owner/export mismatch: "
            f"expected={sorted(EXPECTED)}, got={sorted(exported)}"
        )
    provider_id = exact_binary_identity(provider, osname)
    expected_file = (
        "crypto_provider-0.1.dll" if osname == "windows" else
        "libcrypto_provider.0.1.dylib" if osname == "darwin" else
        "libcrypto_provider.so.0.1"
    )
    details = {}
    for name, image in resources.items():
        dependency_text = imports(image, osname, dumper)
        # For exact versioned provider identity use the native dynamic loader
        # import names, not CMake target aliases or static archive file paths.
        if name != "provider" and expected_file.lower() not in dependency_text.lower():
            raise ValueError(
                f"{name} does not dynamically import ABI 0.1 Provider: "
                f"{image}, expected {expected_file}"
            )
        if "libgmssl.so" in dependency_text.lower() or "gmssl.dll" in dependency_text.lower():
            raise ValueError(f"{name} directly imports GmSSL instead of Crypto: {image}")
        details[name] = {
            "path": str(image),
            "sha256": sha256(image),
            "imports_crypto_provider": name != "provider",
        }
    return {
        "schema": 1, "classification": "PRE_STABLE_SM3_ONLY_NOT_TLS_PROVIDER",
        "platform": osname, "ok": True,
        "native_abi_identity": provider_id,
        "public_exports": sorted(exported),
        "files": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    opts = parser.parse_args()
    try:
        report = audit(opts)
    except (ValueError, OSError, RuntimeError) as err:
        report = {"schema": 1, "ok": False, "errors": [str(err)]}
    opts.report.parent.mkdir(parents=True, exist_ok=True)
    opts.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not report["ok"]:
        print("Crypto native ABI audit: FAIL " + report["errors"][0], file=sys.stderr)
        return 1
    print(
        f"Crypto native ABI 0.1: PASS "
        f"({report['platform']}, three exact exports, two MODULE importers)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
