#!/usr/bin/env bash
# Independent exporter BYTE oracle on one real TLS session.
# Crypto is the already-qualified installed C11 TLS CLIENT.
# A separate TEST-ONLY server links OpenSSL 3 and uses the native
# SSL_export_keying_material() API. Production Crypto links NO OpenSSL.
set -euo pipefail

crypto_client="${1:?installed Crypto C11 client required}"
openssl_oracle_server="${2:?test-only OpenSSL3 reference server required}"
work="${3:?fixture scratch directory required}"
base_port="${4:-9830}"

test -x "$crypto_client"
test -x "$openssl_oracle_server"
test -s "$work/ca.pem"
test -s "$work/leaf.pem"
test -s "$work/leaf-key.pem"
test -s "$work/leaf.der"
openssl version | grep -q '^OpenSSL 3[.]'
leaf_sha256="$(openssl dgst -sha256 -r "$work/leaf.der" | awk '{print $1}')"
[[ "$leaf_sha256" =~ ^[0-9a-f]{64}$ ]]

server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
  # Never upload session-derived keying material or any raw TLS transcript.
  rm -f "$work"/native-exporter-*.secret \
        "$work"/openssl-exporter-*.secret \
        "$work"/native-exporter-*.private \
        "$work"/openssl-exporter-*.private
}
trap cleanup EXIT

for protocol in 12 13; do
  port="$((base_port + protocol - 12))"
  native_secret="$work/native-exporter-$protocol.secret"
  openssl_secret="$work/openssl-exporter-$protocol.secret"

  "$openssl_oracle_server" "$protocol" "$port" \
    "$work/leaf.pem" "$work/leaf-key.pem" "$openssl_secret" \
    >"$work/openssl-exporter-$protocol.private" 2>&1 &
  server_pid=$!
  sleep 1
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "Independent OpenSSL3 exporter oracle could not start" >&2
    exit 1
  fi

  # This Crypto CLIENT already passes strict OpenSSL CA/SAN, ALPN h2,
  # bounded socket I/O, DER identity and authenticated HTTP tests.
  # Optional final argument writes ONLY the no-context TLS exporter bytes.
  if ! "$crypto_client" "$protocol" "$port" "$work/ca.pem" \
      localhost good "$leaf_sha256" "$work/leaf.der" "$native_secret" \
      >"$work/native-exporter-$protocol.private" 2>&1; then
    echo "Crypto C11 client failed independent OpenSSL3 exporter TLS/HTTP test" >&2
    exit 1
  fi

  # The reference must also finish its own TLS/HTTP flow successfully.
  if ! wait "$server_pid"; then
    server_pid=""
    echo "Independent OpenSSL3 server failed a real TLS/HTTP session" >&2
    exit 1
  fi
  server_pid=""
  test -s "$native_secret"
  test -s "$openssl_secret"

  # Strict binary-equivalent 32-byte keying-material comparison; NEVER
  # log, publish, or attach either value. Both are from the SAME session.
  native_hex="$(tr -d '\r\n' < "$native_secret")"
  openssl_hex="$(tr -d '\r\n' < "$openssl_secret")"
  if [[ ! "$native_hex" =~ ^[0-9A-F]{64}$ ]] ||
     [[ ! "$openssl_hex" =~ ^[0-9A-F]{64}$ ]] ||
     [[ "$native_hex" != "$openssl_hex" ]]; then
    echo "Independent OpenSSL3 and Crypto exporter bytes disagree or are missing (TLS $protocol)" >&2
    exit 1
  fi
  unset native_hex openssl_hex
  rm -f "$native_secret" "$openssl_secret" \
    "$work/native-exporter-$protocol.private" \
    "$work/openssl-exporter-$protocol.private"
  echo "Crypto client vs independent OpenSSL3 server: TLS $protocol SAME-SESSION exporter bytes and HTTP PASS"
done

echo "Independent OpenSSL 3 RFC 5705/8446 exporter byte parity: PASS"
