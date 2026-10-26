# Crypto — one static native owner

qigao/crypto is the single source and installed package owner for native
cryptographic algorithms and TLS functionality. It delivers exactly one
static archive and one CMake target:

~~~cmake
find_package(Crypto 0.1 CONFIG REQUIRED)
target_link_libraries(application PRIVATE Salts::Crypto)
~~~

No alternative target namespace, provider DSO, TLSHost binary, libecc library,
separately installed GmSSL archive, or compatibility target is published.
Missing verified input fails at configure time.

The archive combines pinned reviewed GmSSL 3.2 source (TLS1.2/1.3, X.509,
SM2, SM3, SHA and ciphers), C11 TLS facade, bounded CipherBIO, and migrated
SHA256 and Ed448 APIs formerly built by SaltsUtils. The Ed448-required
libecc WEI448 arithmetic and SHAKE256 are compiled privately. The redundant
libecc SHA256 and unsafe pseudo-random generator are deleted; native random
bytes come from the one OS CSPRNG implementation.

## Build inputs

A provenance-verified patched GmSSL checkout and its build-only PIC
libgmssl.a or gmssl.lib must be supplied as CRYPTO_GMSSL_SOURCE and
CRYPTO_GMSSL_STATIC; the project never fetches or substitutes providers.
The build merges those input objects into libsalts_crypto.a (or salts_crypto.lib
on Windows); the staging GmSSL archive is not installed or exported.

The installed CryptoTargets.cmake exports only Salts::Crypto.
The public headers are include/crypto and include/salts/crypto.h.
libecc's dual-license notice is preserved with the SDK; its headers remain private.

## Required exact-head acceptance

The crypto-static-sdk.yml pipeline covers installed C11 and C++17 consumers,
SHA256/SM3/Ed448 RFC vectors, real TLS1.2/1.3 and independent OpenSSL3 peers,
CipherBIO, relocated SDK, single static archive and symbol audits, and fully
source-instrumented ASan/UBSan/LSan and TSan. Migration to static packaging
does not constitute production CNet TLS cutover and does not change the
GmSSL 3.2.0#13 production registry pin. Both remain separately gated.

The old dynamic Provider/Host/DSO architecture has been removed, with no
compatibility shims or provider fallbacks.
