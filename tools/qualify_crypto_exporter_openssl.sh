#!/usr/bin/env bash
# Independent OpenSSL3 exporter byte oracle for the *installed* Crypto TLS
# server image. Test-only secret material stays inside private unuploaded files.
set -euo pipefail

sdk_server="${1:?installed C11 server executable required}"
work="${2:?existing independent OpenSSL fixture workdir required}"
base_port="${3:-9830}"

test -x "$sdk_server"
test -s "$work/ca.pem"
test -s "$work/leaf.pem"
test -s "$work/leaf-key.pem"
openssl version | grep -q '^OpenSSL 3[.]'

server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
  # Deliberately not part of public CI artifacts: includes actual ephemeral
  # TLS-exported bytes. No test logger may print the values on success/fail.
  rm -f "$work"/native-exporter-*.secret "$work"/openssl-exporter-*.secret \
        "$work"/native-exporter-*.private
}
trap cleanup EXIT

for protocol in 12 13; do
  port="$((base_port + protocol - 12))"
  native_secret="$work/native-exporter-$protocol.secret"
  openssl_secret="$work/openssl-exporter-$protocol.secret"
  "$sdk_server" "$protocol" "$port" "$work/leaf.pem" "$work/leaf-key.pem" \
    "$native_secret" >"$work/native-exporter-$protocol.private" 2>&1 &
  server_pid=$!
  sleep 1
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "Independent native Crypto $protocol TLS server failed early" >&2
    exit 1
  fi

  # Python gives a cross-platform bounded subprocess timeout; macOS doesn't
  # guarantee GNU timeout. The OpenSSL *client* owns the peer exporter
  # implementation and writes its diagnostic key material ONLY to .secret.
  python3 - "$openssl_secret" "$protocol" "$port" "$work/ca.pem" <<'PY'
import os
from pathlib import Path
import signal
import subprocess
import sys

secret_path, protocol, port, ca = sys.argv[1:]
command = [
    "openssl", "s_client",
    "-connect", "127.0.0.1:" + port,
    "-servername", "localhost",
    "-verify_return_error", "-verify_hostname", "localhost",
    "-CAfile", ca,
    "-ign_eof", "-ignore_unexpected_eof",
    "-keymatexport", "EXPORTER-Channel-Binding",
    "-keymatexportlen", "32",
]
if protocol == "12":
    command += [
        "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
        "-sigalgs", "rsa_pkcs1_sha256"
    ]
else:
    command += [
        "-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
        "-sigalgs", "rsa_pss_rsae_sha256"
    ]
with Path(secret_path).open("wb") as output:
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        process.communicate(
            input=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            timeout=25,
        )
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        print("OpenSSL exporter peer exceeded 25 second timeout",
              file=sys.stderr)
        raise SystemExit(1)
    if process.returncode != 0:
        print("OpenSSL exporter peer returned a failed TLS/session result",
              file=sys.stderr)
        raise SystemExit(1)
PY

  if ! wait "$server_pid"; then
    server_pid=""
    echo "Crypto TLS $protocol exporter server did not settle" >&2
    exit 1
  fi
  server_pid=""
  test -s "$native_secret"
  test -s "$openssl_secret"

  # Compare the two *independently derived* exporter byte strings from
  # EXACTLY ONE real session; do not print or upload either secret.
  native_hex="$(tr -d '\r\n' < "$native_secret")"
  openssl_hex="$(awk '$1=="Keying" && $2=="material:" {print $3}' \
    "$openssl_secret" | tr -d '\r\n')"
  if [[ ! "$native_hex" =~ ^[0-9A-F]{64}$ ]] ||
     [[ ! "$openssl_hex" =~ ^[0-9A-F]{64}$ ]] ||
     [[ "$native_hex" != "$openssl_hex" ]]; then
    echo "TLS $protocol real Crypto/OpenSSL exporter bytes disagree or are missing" >&2
    exit 1
  fi
  if ! grep -q 'HTTP/1.0 200 OK' "$openssl_secret"; then
    echo "TLS $protocol OpenSSL client did not receive native Crypto HTTP response" >&2
    exit 1
  fi
  rm -f "$native_secret" "$openssl_secret" \
    "$work/native-exporter-$protocol.private"
  echo "Independent OpenSSL 3 TLS $protocol exporter SAME-SESSION bytes and HTTP: PASS"
done

echo "Crypto v1.2 TLS exporter independent OpenSSL 3 oracle: PASS"
