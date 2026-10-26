# Canonical static Crypto source ownership

**Permanent public CMake contract:** package Crypto; target Salts::Crypto;
exactly one installed static archive. Source-of-truth repository qigao/crypto.

~~~text
verified patched GmSSL 3.2 sources --> build-only native static objects
src/provider_sm3.c
src/crypto_tls_gmssl.c
src/crypto_tls_cipher_bio.c
src/crypto_sha256.c  --> GmSSL SHA256_CTX, not libecc SHA256
src/crypto_ed448.c  --> private libecc WEI448 and SHAKE256
src/crypto_random.c --> OS CSPRNG, no untrusted pseudo-random fallback
                |
          one native archive
                |
          Salts::Crypto
~~~

SaltsUtils/crypto is retired in a coordinated source-removal PR. Consumers
still call the sole native owner from Salts::Crypto; there are no duplicate
source files compiled elsewhere, forwarding headers, or public aliases.

No separate module handles, GmSSL runtime archive in the installed SDK,
CryptoTLSConfig, DLL/DSO, or Salts::TLS alias. Original GmSSL qualification
programs remain independent reference tests and are not installed.

Do not merge SaltsUtils source-owner deletion until exact-head 3OS installed
C11/C++17 consumers, RFC8032 Ed448 signatures, sanitizers, binary and symbol
uniqueness gates have succeeded.
