# ASN.1 C11 BER / DER in Salts::Crypto

**One static archive, one public target:** `Salts::Crypto`.
This code was migrated from `qigao/salts-core/asn1` and now lives in
`qigao/crypto/src/asn1` and `include/crypto/asn1*.h`.

The public C ABI is intentionally `crypto_asn1_*` and
`CRYPTO_ASN1_*`: no previous `salts_asn1_*` functions, `salts/asn1*.h`
headers, `Salts::ASN1` dynamic library, aliases, or binary forwards.

- Canonical DER, bounded BER, nested TLV and OID validation.
- Explicit borrowed reader views and owned values with caller-controlled
  memory lifecycle.
- DER ECDSA signature (including P-521 width) and RFC 8410 X25519/Ed25519
  SPKI + PKCS#8 format helpers; no extra cryptographic algorithm engine.
- Original full C conformance cases and C++17 public-header checks
  run as Crypto CTest cases without TinyTest or SaltsCore.
- Independent installed C11/C++17 consumers use only `Salts::Crypto`:

```sh
cmake -S tests/asn1/installed -B build-asn1-installed \
  -DCMAKE_PREFIX_PATH=/path/to/installed-crypto
cmake --build build-asn1-installed
ctest --test-dir build-asn1-installed --output-on-failure
```

The ASN.1 codec is a separate API from the private GmSSL ASN.1 primitives
embedded within its pinned static archive; no GmSSL source/header is copied
or recompiled here. A later explicit review may consolidate low-level
implementations if behavior and DER strictness match; this migration alone
does not substitute GmSSL's internal certificate parser.

## Source-only qualification without GmSSL

The exact same four C/C++17 test bodies can also be compiled directly
with the three Crypto-owned C11 ASN.1 source files as **test executables**,
without installing GmSSL or introducing a second packaged native library:

```sh
cmake -S tests/asn1/standalone -B build-asn1-source -G Ninja
cmake --build build-asn1-source
ctest --test-dir build-asn1-source --output-on-failure
```

This target is strictly test-only and is never installed or exported.
