#!/usr/bin/env bash
# Independent OpenSSL3 s_client against an actual installed Crypto::TLS
# SERVER. Keep the reverse-role gate separate from the already-qualified
# Crypto-client/OpenSSL-server exporter oracle.
set -euo pipefail

crypto_server="${1:?installed opaque C11 Crypto TLS server required}"
work="${2:?existing private OpenSSL fixture scratch dir required}"
base_port="${3:-9900}"

test -x "$crypto_server"
test -s "$work/ca.pem"
test -s "$work/leaf.pem"
test -s "$work/leaf-key.pem"
openssl version | grep -q '^OpenSSL 3[.]'

server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  # Unlink transient material on EVERY exit including failed handshake.
  rm -f "$work"/reverse-crypto-*.secret \
        "$work"/reverse-openssl-*.private \
        "$work"/reverse-server-*.private
}
trap cleanup EXIT

for proto in 12 13; do
  port="$((base_port + proto - 12))"
  server_log="$work/reverse-server-$proto.private"
  openssl_log="$work/reverse-openssl-$proto.private"
  secret="$work/reverse-crypto-$proto.secret"

  "$crypto_server" "$proto" "$port" "$work/leaf.pem" \
    "$work/leaf-key.pem" "$secret" >"$server_log" 2>&1 &
  server_pid=$!
  sleep 1
  kill -0 "$server_pid" 2>/dev/null || {
    echo "Crypto TLS $proto test server did not enter accept" >&2; exit 1;
  }

  if ! python3 - "$proto" "$port" "$work/ca.pem" "$openssl_log" <<'PY'
from pathlib import Path
import os
import re
import signal
import subprocess
import sys

protocol, port, ca_path, logfile = sys.argv[1:]
args = [
    "openssl", "s_client", "-connect", "127.0.0.1:" + port,
    "-servername", "localhost",
    "-CAfile", ca_path, "-verify_return_error",
    "-verify_hostname", "localhost",
    "-keymatexport", "EXPORTER-Channel-Binding", "-keymatexportlen", "32",
    "-ign_eof", "-ignore_unexpected_eof",
]
if protocol == "12":
    args += ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
             "-sigalgs", "rsa_pkcs1_sha256"]
else:
    args += ["-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
             "-sigalgs", "rsa_pss_rsae_sha256"]
with Path(logfile).open("wb") as output:
    proc = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        proc.communicate(
            input=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", timeout=22
        )
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        print("Reverse OpenSSL peer timed out, TLS " + protocol,
              file=sys.stderr)
        sys.exit(1)
    if proc.returncode:
        log = Path(logfile).read_text(errors="replace")
        # This output contains exporter material. Do not print it!
        print("Reverse OpenSSL TLS {} failed: rc={} verified={} http={}".format(
            protocol, proc.returncode,
            ("verify return code: 0" in log.lower()
             or "verification: ok" in log.lower()),
            "HTTP/1.0 200" in log
        ), file=sys.stderr)
        sys.exit(1)
PY
  then
    # The server might still be unwinding the failed handshake. Show only
    # bounded state/length diagnostics, never the output containing secrets.
    sleep 0.2
    grep '^CRYPTO_TLS_PRIVATE_HANDSHAKE_DIAG ' "$server_log" >&2 || true
    grep '^Crypto test-only TLS server/exporter failed ' "$server_log" >&2 || true
    echo "Reverse OpenSSL TLS $proto peer did not qualify" >&2
    exit 1
  fi

  if ! wait "$server_pid"; then
    server_pid=""
    # Print ONLY the approved private state/type/length diagnostic
    # without accidentally publishing a TLS transcript or export material.
    grep '^CRYPTO_TLS_PRIVATE_HANDSHAKE_DIAG ' "$server_log" >&2 || true
    grep '^Crypto test-only TLS server/exporter failed ' "$server_log" >&2 || true
    echo "Crypto TLS $proto server failed authenticated TLS/HTTP" >&2
    exit 1
  fi
  server_pid=""
  test -s "$secret"
  if ! grep -q 'HTTP/1.0 200' "$openssl_log"; then
    echo "OpenSSL TLS $proto did not receive Crypto authenticated HTTP" >&2
    exit 1
  fi
  # Do NOT write the TLS export secret to CI logs; later add a separate
  # independently verified peer exporter comparison after handshake passes.
  rm -f "$openssl_log" "$server_log" "$secret"
  echo "Crypto shared TLS server vs OpenSSL3 s_client TLS $proto handshake and HTTP PASS"
done
