# qigao/crypto — retiring; source moves to qigao/salts-core

> **DEPRECATED / RETIREMENT IN PROGRESS.** New ASN1, Crypto and TLS
> development belongs in [qigao/salts-core](https://github.com/qigao/salts-core)
> under its module-local `asn1/` and `crypto/` directories.
> This repository remains read/write only until all original code, tests,
> downstream consumers and CI are validated, then it should be archived
> read-only. Do not delete historical source or publish new packages here.

Tracking: [retirement #45](https://github.com/qigao/crypto/issues/45),
[SaltsCore migration PR #75](https://github.com/qigao/salts-core/pull/75),
[native TLS gate PR #74](https://github.com/qigao/salts-core/pull/74).
Original [mTLS PR #43](https://github.com/qigao/crypto/pull/43)
has been copied, including its tests, but still requires exact-head
acceptance before it can be superseded.

---

## Historical standalone-repository documentation
This **single repository** contains two independently buildable native modules:

| Module | Target | Owns | Depends on |
| --- | --- | --- | --- |
| [asn1/](asn1/) | `Salts::ASN1` (static) | BER/DER, TLV, OID, canonical encoding, bounded validation, owned Value Tree | C11 only |
| [crypto/](crypto/) | `Salts::Crypto` (static) | GmSSL-backed TLS, SHA256, Ed448, ECDSA DER and RFC 8410 key formats | `Salts::ASN1`, pinned GmSSL static input |

**ASN.1 is one standard protocol codec**, not a Crypto-private parser. `salts-net`
uses `Salts::ASN1` directly for SNMP and LDAP, without importing GmSSL.
Crypto consumes it for signature and key container formats and does not
recompile Reader/Value sources. No second provider, old API compatibility
layer, or silent fallback is supplied.

## Independent ASN.1 source build (no GmSSL)

```sh
cmake -S asn1 -B build-asn1 -DBUILD_TESTING=ON
cmake --build build-asn1 --parallel
ctest --test-dir build-asn1 --output-on-failure
cmake --install build-asn1 --prefix "$PWD/asn1-sdk"
cmake -S asn1/tests/installed -B build-asn1-consumer \
  "-DCMAKE_PREFIX_PATH=$PWD/asn1-sdk"
cmake --build build-asn1-consumer --parallel
ctest --test-dir build-asn1-consumer --output-on-failure
```

To run the root project without GmSSL:
`cmake -S . -B build-codec -DSALTS_CRYPTO_BUILD_CRYPTO=OFF`.

## Both modules together

Install exact GmSSL from qigao/vcpkg-cache using
`crypto/vcpkg.json` as the vcpkg manifest root. Then:

```sh
cmake -S . -B build -DBUILD_TESTING=ON \
  "-DCRYPTO_GMSSL_ROOT=$PWD/crypto/vcpkg_installed/x64-linux"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/sdk"
```

The installed SDK contains **one** `libsalts_asn1.a` and **one**
`libsalts_crypto.a` (Windows: the matching `.lib` archives), exported as
`find_package(ASN1 0.1 CONFIG REQUIRED)` and
`find_package(Crypto 0.1 CONFIG REQUIRED)`. The Crypto package declares
`find_dependency(ASN1)`. Both are `Salts::XXX` targets. No
`SaltsCore::` or `Crypto::` alias is supported.

`cmake -S crypto` remains supported with installed `Salts::ASN1`:
pass `-DCMAKE_PREFIX_PATH=<asn1-sdk>` and
`-DCRYPTO_GMSSL_ROOT=<installed-triplet-prefix>`.
The Crypto module owns its reviewed private libecc input at
`crypto/vendor/libecc/`. Pinned GmSSL extension sources remain in
`vendor/gmssl-extensions/` for qigao/vcpkg-cache's immutable source pin;
they are not another installed module or a second compiled Crypto provider.

The production API cutover is gated by installed C11/C++17 consumers and
SNMP/LDAP/USM/X.509 wire-equivalence on exact source HEADs. No released ABI
is implied by this draft.
