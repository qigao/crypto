# Salts::Crypto — one static archive, GmSSL supplied by vcpkg-cache

`qigao/crypto` owns the **Crypto facade, algorithm API and libecc integration**.
`qigao/vcpkg-cache/ports/gmssl` is the **sole source, patch, version and binary
package owner** for GmSSL. There is no `providers/gmssl/`, local GmSSL clone,
source assembly, fallback or compatibility Provider in this repository.

The sole exported installed library is `Salts::Crypto`:

```cmake
find_package(Crypto 0.1 CONFIG REQUIRED)
target_link_libraries(application PRIVATE Salts::Crypto)
```

Its one installed `libsalts_crypto.a` or `salts_crypto.lib` combines the
Crypto-owned C11 TLS/CipherBIO/SHA256/Ed448 sources, reviewed private libecc
Ed448-only objects, **and the GmSSL static archive obtained from vcpkg**.
`GmSSL::GmSSL` is build-only, never exported or transitively linked by an
installed Crypto target; no second GmSSL SDK archive/DSO is shipped by Crypto.
Crypto also installs the pinned GmSSL Apache-2.0 license and vendored
libecc BSD license with the combined archive.

## Install and build

Install the canonical pinned `gmssl 3.2.0#13` port from
[qigao/vcpkg-cache](https://github.com/qigao/vcpkg-cache).
The Crypto repo owns its `vcpkg.json` manifest; the shared vcpkg setup
action supplies pinned tooling and `VCPKG_OVERLAY_PORTS`. CI uses the
immutable vcpkg-cache commit
`2e214ae44a3e3244eded5db6361194576356fc9e`.

For a GitHub Actions runner after executing that setup action:

```bash
python3 tools/ci/install_vcpkg_gmssl.py linux-x64
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  "-DCRYPTO_GMSSL_ROOT=$GITHUB_WORKSPACE/vcpkg_installed/x64-linux"
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /tmp/crypto-sdk
```

The installer rejects any nonmatching portfile, manifest or package-config
Git blob; it never falls back to the public registry or an unverified local
`gmssl.a`. Other qualified target triplets are selected by the script for
Windows, macOS, Android ARM64 and iOS ARM64.

Published direct GmSSL access is intentionally narrow: the Crypto SDK installs
the exact `<gmssl/sm3.h>` from the vetted vcpkg package, and callers may use
`sm3_init/update/finish` from **the same combined archive**. Other GmSSL
headers remain private to the Crypto build. Public Crypto-owned interfaces are
`<crypto/sha256.h>`, `<crypto/ed448.h>`, `<crypto/tls.h>`,
`<crypto/tls_ext.h>`, `<crypto/tls_peer.h>`, and `<crypto/cipher_bio.h>`.
There is no `<crypto/provider.h>` or `<salts/crypto.h>` legacy entrypoint.

## Acceptance policy

Crypto CI verifies Linux/Windows/macOS installed/relocated C11 and C++17
consumers, real TLS1.2/1.3 with independent OpenSSL3 CA/SAN/HRR/exporter
negative gates, RFC8032 Ed448, SHA256, direct SM3, Android/iOS cross-built
installed SDK and static symbol cardinality. Source ASan/UBSan/LSan and TSan
gates instrument Crypto/libecc **but not the cached GmSSL archive**. Fully
source-instrumented GmSSL belongs in vcpkg-cache's own package qualification,
using the same exact port identity.

A failure against the official vcpkg port is a genuine migration blocker. Fix
the vcpkg-cache port in a separately qualified change; do not restore
`providers/gmssl`, relax TLS tests, substitute OpenSSL, or silently drop
features. This repository migration alone does not release packages, switch
production CNet, or alter its current GmSSL 3.2.0#13 pin.
