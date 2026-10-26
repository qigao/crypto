#!/usr/bin/env python3
"""Run original GmSSL-vs-OpenSSL peer contracts, without vcpkg or a fallback.

This is a qualification runner, not a production TLS API. The two original
shell scripts, source patches and certificate-policy assertions stay unchanged.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "providers" / "gmssl" / "tests"
CASES = (
    ("tls12_rsa_mtls", "tls12-rsa-mtls-interop.sh", 9450),
    ("tls12_tls13_p384_issuer", "tls-p384-issuer-interop.sh", 9460),
)


def run_one(bash, binary, name, script, port, evidence, scratch, deadline):
    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryDirectory(prefix="gmssl-interop-", dir=scratch) as parent:
        work = Path(parent) / "fixture"
        proc = subprocess.Popen(
            [bash, str(script), str(binary), str(work), str(port)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=deadline)
        except subprocess.TimeoutExpired:
            # Kill the whole session, including background OpenSSL/GmSSL peers.
            # Killing only the shell would leave a listener on the fixed ports.
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        code = proc.returncode
    elapsed = round(time.monotonic() - started, 3)
    (evidence / (name + ".stdout.log")).write_text(stdout, encoding="utf-8")
    (evidence / (name + ".stderr.log")).write_text(stderr, encoding="utf-8")
    return {
        "name": name,
        "script": script.name,
        "base_port": port,
        "exit_code": code,
        "timed_out": timed_out,
        "elapsed_seconds": elapsed,
        "passed": code == 0 and not timed_out,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gmssl", type=Path, required=True,
                        help="compiled patched GmSSL 3.2 CLI binary")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 600:
        parser.error("timeout must be between 1 and 600 seconds per case")

    binary = args.gmssl.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("missing executable original patched GmSSL CLI: " + str(binary))
    bash = shutil.which("bash")
    openssl = shutil.which("openssl")
    if not bash or not openssl:
        parser.error("both bash and independent openssl CLI must be installed")
    version = subprocess.run(
        [openssl, "version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if not version.startswith("OpenSSL 3."):
        parser.error("OpenSSL 3 CLI is required; no LibreSSL/alternative fallback: "
                     + version)

    evidence = args.evidence_dir.resolve()
    scratch = args.scratch_dir.resolve()
    if evidence == scratch or evidence in scratch.parents or scratch in evidence.parents:
        parser.error("scratch and evidence directories must be independent")
    evidence.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    results = []
    for name, filename, port in CASES:
        script = ORIGINAL / filename
        if not script.is_file():
            parser.error("missing frozen original interop contract: " + str(script))
        try:
            result = run_one(bash, binary, name, script, port, evidence, scratch,
                             args.timeout)
        except OSError as exc:
            result = {"name": name, "script": filename, "passed": False,
                      "error": str(exc)}
        results.append(result)
        print("{}: {} {}".format(
            name, "PASS" if result["passed"] else "FAIL", result), flush=True)

    receipt = {
        "classification": "ORIGINAL_GMSSL_PRIVATE_OPENSSL3_INTEROP_NOT_PROVIDER_ABI",
        "gmssl_binary": str(binary),
        "openssl_version": version,
        "cases": results,
        "passed": all(case["passed"] for case in results),
    }
    (evidence / "interop-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
