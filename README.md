# Salts::Crypto

This repository owns the Crypto C11 facade, SHA256/Ed448 adapters, bounded TLS
CipherBIO and private libecc Ed448 arithmetic. It installs **one** native static
archive and exactly one CMake target:

```cmake
find_package(Crypto 0.1 CONFIG REQUIRED)
target_link_libraries(application PRIVATE Salts::Crypto)
```

GmSSL source, patches, version registration and binary packages belong
**exclusively** to [qigao/vcpkg-cache](https://github.com/qigao/vcpkg-cache)
(`ports/gmssl`). Crypto does not contain a `providers/gmssl/` copy, download
upstream GmSSL independently, install a separate GmSSL library, or export
`GmSSL::GmSSL`. It embeds the installed vcpkg static GmSSL objects into the
single `Salts::Crypto` archive.

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
  "-DCRYPTO_GMSSL_ROOT=$PWD/vcpkg_installed/x64-linux"
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
