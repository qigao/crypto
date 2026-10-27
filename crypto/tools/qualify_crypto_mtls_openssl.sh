#!/usr/bin/env bash
# Independent OpenSSL 3 mTLS peer matrix for the installed static Salts::Crypto.
# Test peers may link OpenSSL; Crypto itself must not link OpenSSL. Private
# ephemeral keys and exporter secrets never enter CI logs or artifacts.
set -euo pipefail
native_server="$1"
openssl_client="$2"
native_client="$3"
work="$4"
base="${5:-10900}"
test -x "$native_server"
test -x "$openssl_client"
test -x "$native_client"
openssl version | grep -q '^OpenSSL 3[.]'
umask 077
mkdir -p "$work"
tmp="$(mktemp -d "$work/mtls.XXXXXXXX")"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -keyout "$tmp/ca-key.pem" -out "$tmp/ca.pem" \
  -subj "/CN=mtls-qualified-trust-root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >"$tmp/generate.private" 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -keyout "$tmp/wrongca-key.pem" -out "$tmp/wrongca.pem" \
  -subj "/CN=mtls-UNTRUSTED-issuer" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >>"$tmp/generate.private" 2>&1
cat >"$tmp/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF
cat >"$tmp/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
cat >"$tmp/eku.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF
cat >"$tmp/intermediate.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
# RSA identities are chosen to match the existing C11 standard TLS1.2
# ECDHE-RSA and TLS1.3 RSA-PSS profiles, not TLCP/SM2 dual identities.
for item in server client wrongca eku expired chain intermediate; do
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$tmp/$item-key.pem" -out "$tmp/$item.csr" \
    -subj "/CN=$item" >>"$tmp/generate.private" 2>&1
done
sign() {
  local item="$1" ca="$2" cakey="$3" ext="$4"
  openssl x509 -req -in "$tmp/$item.csr" -CA "$tmp/$ca.pem" \
    -CAkey "$tmp/$cakey.pem" -CAcreateserial -sha256 -days 2 \
    -extfile "$tmp/$ext.ext" -out "$tmp/$item.pem" \
    >>"$tmp/generate.private" 2>&1
}
sign server ca ca-key server
sign client ca ca-key client
sign wrongca wrongca wrongca-key client
sign eku ca ca-key eku
sign intermediate ca ca-key intermediate
# This leaf is signed by a valid intermediate, but the TLS client sends ONLY
# the leaf. There is no intermediary in the peer chain to the trusted root.
sign chain intermediate intermediate-key client
cat >"$tmp/ca.cnf" <<EOF
[ca]
default_ca=issuer
[issuer]
database=$tmp/index.txt
serial=$tmp/serial
new_certs_dir=$tmp/newcerts
certificate=$tmp/ca.pem
private_key=$tmp/ca-key.pem
default_md=sha256
policy=policy_any
unique_subject=no
[policy_any]
commonName=supplied
[client_usage]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
: >"$tmp/index.txt"
mkdir -p "$tmp/newcerts"
printf '1000\n' >"$tmp/serial"
openssl ca -batch -config "$tmp/ca.cnf" -extensions client_usage \
  -startdate 20200101000000Z -enddate 20200102000000Z \
  -in "$tmp/expired.csr" -out "$tmp/expired.pem" \
  >>"$tmp/generate.private" 2>&1

openssl verify -CAfile "$tmp/ca.pem" -purpose sslserver \
  -verify_hostname localhost "$tmp/server.pem" >"$tmp/verify.private"
openssl verify -CAfile "$tmp/ca.pem" -purpose sslclient \
  "$tmp/client.pem" >>"$tmp/verify.private"
if openssl verify -CAfile "$tmp/ca.pem" -purpose sslclient \
   "$tmp/eku.pem" >>"$tmp/verify.private" 2>&1; then
  echo "bad EKU fixture erroneously admitted" >&2; exit 1
fi
if openssl verify -CAfile "$tmp/ca.pem" -purpose sslclient \
   "$tmp/expired.pem" >>"$tmp/verify.private" 2>&1; then
  echo "expired fixture erroneously admitted" >&2; exit 1
fi
if openssl verify -CAfile "$tmp/ca.pem" -purpose sslclient \
   "$tmp/chain.pem" >>"$tmp/verify.private" 2>&1; then
  echo "incomplete chain fixture erroneously admitted" >&2; exit 1
fi
if openssl verify -CAfile "$tmp/ca.pem" -purpose sslclient \
   "$tmp/wrongca.pem" >>"$tmp/verify.private" 2>&1; then
  echo "wrong issuer fixture erroneously admitted" >&2; exit 1
fi
openssl x509 -in "$tmp/server.pem" -outform DER -out "$tmp/server.der"
sha="$(openssl dgst -sha256 -r "$tmp/server.der" | awk '{print $1}')"
[[ "$sha" =~ ^[0-9a-f]{64}$ ]]

case_files() {
  # pair result variables assigned without eval, avoiding external shell code.
  cert=""
  key=""
  case "$1" in
    missing) ;;
    wrongca|eku|expired|chain)
      cert="$tmp/$1.pem"; key="$tmp/$1-key.pem" ;;
    *) echo "unknown negative case" >&2; exit 1 ;;
  esac
}
port="$base"
for proto in 12 13; do
  # Direction A: the native Crypto C11 SERVER must demand and verify the
  # independent OpenSSL3 client's certificate, with a real HTTP exchange.
  port="$((port+1))"
  "$native_server" "$proto" "$port" "$tmp/server.pem" "$tmp/server-key.pem" \
    "$tmp/crypto.secret" "$tmp/ca.pem" >"$tmp/native.private" 2>&1 &
  server_pid=$!
  sleep 1
  if ! "$openssl_client" "$proto" "$port" "$tmp/ca.pem" localhost p256 \
    "$tmp/openssl.secret" "$tmp/client.pem" "$tmp/client-key.pem" \
    >"$tmp/openssl.private" 2>&1; then
    echo "Crypto server/OpenSSL3 TLS $proto valid REQUIRED client failed" >&2
    exit 1
  fi
  if ! wait "$server_pid"; then
    server_pid=""
    echo "Crypto server TLS $proto did not complete authenticated HTTP" >&2
    exit 1
  fi
  server_pid=""
  test -s "$tmp/crypto.secret"
  test -s "$tmp/openssl.secret"
  cmp -s "$tmp/crypto.secret" "$tmp/openssl.secret" || {
    echo "mTLS exporter mismatch for TLS $proto" >&2; exit 1;
  }
  grep -q "handshake_complete protocol=\$proto auth=1" "$tmp/native.private"
  rm -f "$tmp/crypto.secret" "$tmp/openssl.secret"
  echo "mTLS Crypto-server/OpenSSL3-client TLS $proto: positive PASS"

  for negative in missing wrongca eku expired chain; do
    case_files "$negative"
    port="$((port+1))"
    "$native_server" "$proto" "$port" "$tmp/server.pem" \
      "$tmp/server-key.pem" "$tmp/rejected.secret" "$tmp/ca.pem" \
      >"$tmp/native.private" 2>&1 &
    server_pid=$!
    sleep 1
    if [[ -n "$cert" ]]; then
      "$openssl_client" "$proto" "$port" "$tmp/ca.pem" localhost p256 \
        "$tmp/unexpected.secret" "$cert" "$key" \
        >"$tmp/openssl.private" 2>&1 || true
    else
      "$openssl_client" "$proto" "$port" "$tmp/ca.pem" localhost p256 \
        "$tmp/unexpected.secret" >"$tmp/openssl.private" 2>&1 || true
    fi
    if wait "$server_pid"; then
      server_pid=""
      echo "Crypto TLS $proto allowed $negative client authentication!" >&2
      exit 1
    fi
    server_pid=""
    # Prove rejection occurred in handshake, not in a later HTTP/exporter step.
    if ! grep -Eq 'failed .*phase=3,.*handshake=0,.*client_auth=1' \
        "$tmp/native.private"; then
      echo "Crypto TLS $proto $negative was not a verified handshake rejection" >&2
      exit 1
    fi
    test ! -e "$tmp/rejected.secret" && test ! -e "$tmp/unexpected.secret"
    echo "mTLS Crypto-server/OpenSSL3-client TLS $proto: $negative rejected PASS"
  done

  # Direction B: installed C11 Crypto CLIENT identity against OpenSSL3
  # SERVER with SSL_VERIFY_FAIL_IF_NO_PEER_CERT (-Verify).
  port="$((port+1))"
  openssl_args=(-accept "127.0.0.1:$port"
    -cert "$tmp/server.pem" -key "$tmp/server-key.pem"
    -cert_chain "$tmp/ca.pem" -verifyCAfile "$tmp/ca.pem"
    -Verify 1 -www -quiet -alpn "h2,http/1.1")
  if [[ "$proto" == 12 ]]; then
    openssl_args+=(-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256
      -sigalgs rsa_pkcs1_sha256)
  else
    openssl_args+=(-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
      -sigalgs rsa_pss_rsae_sha256 -groups P-256)
  fi
  openssl s_server "${openssl_args[@]}" \
    >"$tmp/ossl-server.private" 2>&1 &
  server_pid=$!
  sleep 1
  "$native_client" "$proto" "$port" "$tmp/ca.pem" localhost good \
    "$sha" "$tmp/server.der" "$tmp/crypto-nocontext.secret" \
    "$tmp/crypto-emptycontext.secret" "$tmp/client.pem" "$tmp/client-key.pem" \
    >"$tmp/native-client.private" 2>&1 || {
      echo "Crypto client/OpenSSL3 REQUIRED server TLS $proto valid identity failed" >&2
      exit 1;
    }
  rm -f "$tmp/crypto-nocontext.secret" "$tmp/crypto-emptycontext.secret"
  echo "mTLS Crypto-client/OpenSSL3-server TLS $proto: positive PASS"

  # Negative missing identity and invalid leaf purposes: no HTTP success.
  for negative in missing eku wrongca expired chain; do
    case_files "$negative"
    if [[ -n "$cert" ]]; then
      if "$native_client" "$proto" "$port" "$tmp/ca.pem" localhost good \
        "$sha" "$tmp/server.der" "$tmp/negative-one.secret" \
        "$tmp/negative-two.secret" "$cert" "$key" \
        >"$tmp/native-client.private" 2>&1; then
        echo "OpenSSL TLS $proto server accepted $negative Crypto client!" >&2
        exit 1
      fi
    else
      if "$native_client" "$proto" "$port" "$tmp/ca.pem" localhost good \
        "$sha" "$tmp/server.der" \
        >"$tmp/native-client.private" 2>&1; then
        echo "OpenSSL TLS $proto server accepted anonymous Crypto client!" >&2
        exit 1
      fi
    fi
    test ! -e "$tmp/negative-one.secret"
    test ! -e "$tmp/negative-two.secret"
    echo "mTLS Crypto-client/OpenSSL3-server TLS $proto: $negative rejected PASS"
  done
  cleanup
done
echo "Independent OpenSSL3/Crypto two-role mTLS TLS1.2+TLS1.3: PASS"
