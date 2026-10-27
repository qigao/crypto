# Standalone native ASN.1 codec — export candidate

This is a standalone, provider-neutral C11 package staged on a **NON-MERGEABLE
export branch** in qigao/crypto until the dedicated qigao/asn1 repository
exists. **Do not merge this branch into Crypto master**: doing so replaces the
Crypto source tree. Move this tree as a whole to the new repository.

- Owns bounded BER/DER TLV reader, validator, encoder, OID, and opaque owned
  value tree. No GmSSL, TLS, Core, Crypto, CMeta, CFlow or TinyTest dependency.
- One static library and target **Salts::ASN1**, headers in include/salts,
  canonical C symbols salts_asn1_* (intentional breaking ownership change).
- ECDSA signature / RFC8410 key formats stay with Crypto.
- SNMP/LDAP protocols and MIB schema grammar stay with SaltsNet.
- No legacy aliases, binary parser shims, duplicated algorithms, or fallback.

Build and run standalone tests:

    cmake -S . -B build -DBUILD_TESTING=ON
    cmake --build build --parallel
    ctest --test-dir build --output-on-failure
    cmake --install build --prefix "$PWD/install"
    cmake -S tests/installed -B build-installed "-DCMAKE_PREFIX_PATH=$PWD/install"
    cmake --build build-installed --parallel
    ctest --test-dir build-installed --output-on-failure

Consumers use find_package(ASN1 0.1 CONFIG REQUIRED) and Salts::ASN1.

## Provenance

General-purpose C11 sources mechanically relocated from
qigao/crypto@b09a981c (the merged ASN.1 owner, originating in salts-core).
Only the function, macro and header namespace changes:
crypto_asn1_* to salts_asn1_*,
CRYPTO_ASN1_* to SALTS_ASN1_* and
crypto/asn1*.h to salts/asn1*.h.
The parser safety boundaries and allocation/ownership logic are unchanged.
Original reader and value conformance tests are carried over.

Do not switch the production Crypto and SaltsNet owners until this
separate package is published, reproducibly qualified and real installed
C11/C++17 plus SNMP/LDAP protocol acceptance is green.
