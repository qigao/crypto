# Salts::Crypto

This repository owns the Crypto C11 facade, SHA256/Ed448 adapters, bounded TLS
CipherBIO and private libecc Ed448 arithmetic. It installs **one** native static
archive and exactly one **Crypto** CMake target (plus the separately imported
`Salts::ASN1` native codec target):

```cmake
find_package(Crypto 0.1 CONFIG REQUIRED)
target_link_libraries(application PRIVATE Salts::Crypto)
```

The pinned **upstream GmSSL** source checkout, package assembly, ordered
security patches and version registry belong to
[qigao/vcpkg-cache](https://github.com/qigao/vcpkg-cache) (`ports/gmssl`).
The six additional native C implementations and their private/public headers
now live **only in Crypto** at `vendor/gmssl-extensions/`.
The GmSSL vcpkg port obtains these immutable source inputs from a pinned
Crypto commit; it builds them once into the GmSSL static archive.
Crypto's own CMake does **not** compile those extensions again and exports
only its existing `Salts::Crypto` archive. There is no `providers/gmssl/`
source clone, second installed GmSSL archive, dynamic Provider or alternate
target alias.

## Build using the installed vcpkg-cache GmSSL port

The reviewed port is `gmssl 3.2.0#14`, incorporated into the vcpkg-cache
repository at commit
`d2ce09ebd3cf127338eea5c8d87a588aeb9d127c`
([PR #214](https://github.com/qigao/vcpkg-cache/pull/214)). Its
source/patch/package Git tree is
`730635344d5ffa64fcf55eb959aa92c79cedd15c` (97 tracked files).
The historical `#13` version remains available to consumers explicitly
pinned to that registry version.

For example, on Linux with canonical vcpkg already installed and
`VCPKG_ROOT` set:

```bash
# Check out qigao/vcpkg-cache at the merged port revision.
git -C ../vcpkg-cache checkout d2ce09ebd3cf127338eea5c8d87a588aeb9d127c
export VCPKG_OVERLAY_PORTS="$PWD/../vcpkg-cache/ports"

# Fail closed before consuming any source or package not in the reviewed port.
python3 tools/verify_vcpkg_gmssl.py \
  --port "$VCPKG_OVERLAY_PORTS/gmssl"

"$VCPKG_ROOT/vcpkg" install \
  --x-manifest-root="$PWD" \
  --x-install-root="$PWD/vcpkg_installed" \
  --triplet x64-linux \
  --overlay-ports="$VCPKG_OVERLAY_PORTS"

python3 tools/verify_vcpkg_gmssl.py \
  --port "$VCPKG_OVERLAY_PORTS/gmssl" \
  --prefix "$PWD/vcpkg_installed/x64-linux"

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON \
  "-DCRYPTO_GMSSL_ROOT=$PWD/vcpkg_installed/x64-linux" \
  "-DCMAKE_PREFIX_PATH=$PWD/../asn1/install"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
python3 tools/audit_static_crypto.py \
  --prefix "$PWD/install" --report "$PWD/build/static-audit.json"
```

Use the appropriate vcpkg triplet, toolchain and SDK for macOS, Windows,
Android or iOS. The `CRYPTO_GMSSL_ROOT` parameter always refers to an
**installed target-triplet prefix**, not a GmSSL source checkout. The CMake
configure rejects a missing or nonstatic library and an imported archive from
outside that prefix. The standalone verifier checks the complete reviewed
vcpkg port tree and optional installed headers, library and license.

## Installed headers

- `crypto/sha256.h`, `crypto/ed448.h`, `crypto/status.h`: algorithms.
- `crypto/tls.h`, `crypto/tls_ext.h`, `crypto/tls_peer.h`,
  `crypto/cipher_bio.h`: bounded TLS session and ciphertext ownership.
- `gmssl/sm3.h`: direct use of GmSSL's SM3 implementation from the
  **same static `Salts::Crypto` archive**.

The generic `crypto/provider.h`, historical `salts/crypto.h`, dynamic
Crypto Provider/Host, compatibility aliases and independently installed GmSSL
archive are intentionally absent. Apache-2.0 GmSSL and BSD libecc licenses
are installed with Crypto's static SDK.

## GmSSL extension source provenance

The follow-up vcpkg GmSSL `3.2.0#15` candidate reads the exact
`vendor/gmssl-extensions/` source tree from this repository, without
storing duplicate production `.c/.h` under `vcpkg-cache/ports/gmssl`.
This is a source-only ownership handoff; the already qualified `#14`
port remains available, and current Crypto and production CNet pins
are not changed by adding those source files.

## Independent ASN.1, Crypto-specific key formats

The generic BER/DER Reader, Validator, Encoder, OID and Owned Value Tree
belong solely to **standalone static `Salts::ASN1`**, not Crypto.
Install the independently qualified ASN1 0.1 CMake package first and make it
visible via `CMAKE_PREFIX_PATH`. The sole Crypto archive imports
`Salts::ASN1` and does **not** compile the generic parser or value tree again.
ASN1 owns `<salts/asn1.h>`, `<salts/asn1_value.h>` and `salts_asn1_*`.

Crypto still owns `<crypto/asn1_crypto.h>` and the `crypto_asn1_ecdsa_*`
and `crypto_asn1_rfc8410_*` X9.62/RFC 8410 key-format profiles.
Those functions return the canonical `salts_asn1_status` codes; no
legacy `crypto_asn1_reader_*` or `crypto_asn1_value_*` forwards remain.
Private GmSSL ASN.1 internals remain confined to its existing static objects.

For independent installed Crypto C11/C++17 consumers, put both the
Crypto and ASN1 installation prefixes in `CMAKE_PREFIX_PATH`.
No SaltsCore, CMeta, fallback provider or additional Crypto static archive
is introduced. This is an intentional source/ABI change, not a compatible
update to previously published Crypto headers.

## Tests and maintenance

The repository retains C11/C++17 installed consumers, SHA256/SM3/Ed448
vectors, TLS 1.2/1.3/OpenSSL3 negative test programs, native lifecycle and
CipherBIO tests, cross-platform consumer smoke tests and the static symbol
audit. These can be executed **manually** or by downstream qualification.

The repository's GitHub Actions workflows and CI-specific bootstrap scripts
were removed as requested; it no longer runs automatic Crypto CI on PRs.
GmSSL **source-level** sanitizer and conformance validation remains owned by
vcpkg-cache's independent GmSSL port validation.

No package release or production CNet migration is implied here. CNet's
explicitly pinned historical GmSSL `3.2.0#13` is not changed.
The remaining expanded TLS1.3 encrypted-handshake framing, shared CCS
admission and second-ClientHello padding parity is tracked in
[vcpkg-cache issue #213](https://github.com/qigao/vcpkg-cache/issues/213).
