# Canonical static Crypto ownership

The only public installed native target is **`Salts::Crypto`**, built as
one static library. There is no generic Crypto Provider, DSO, duplicated
GmSSL archive, or alternate CMake namespace.

```text
qigao/crypto/vendor/gmssl-extensions/
    six C11 extension implementations, six headers,
    one private TLS 1.3 framing header
                 |
                 | exact Git source-only input
                 v
qigao/vcpkg-cache/ports/gmssl
    upstream guanzhi/GmSSL source pin
    ordered GmSSL patch scripts and security hardening
    GmSSL package/registry/ABI/sanitizer qualification
                 |
                 | one installed vcpkg static GmSSL archive
                 v
qigao/crypto/CMakeLists.txt
    private build-time GmSSL::GmSSL import
    + C11 TLS/CipherBIO facade and SHA256/Ed448
    + private libecc Ed448 objects and OS CSPRNG
                 |
                 v
          one installed Salts::Crypto archive
```

Crypto owns the additional GmSSL C/H **source files**, including the
legacy MD5 and DES compatibility implementations, AES Key Wrap, RSA,
P-384 verification, and the private TLS1.3 handshake reader.
vcpkg-cache owns the **upstream GmSSL source selection and adaptation**,
distribution, version history, and package qualification. A new port
revision can fetch immutable Crypto source inputs and compile them once
into its static GmSSL package; Crypto's own native target does not
compile the additions a second time.

Historical `gmssl 3.2.0#14` is the accepted Crypto build input at
`vcpkg-cache@d2ce09ebd3cf127338eea5c8d87a588aeb9d127c`.
The source-ownership package change is separately qualified as
`gmssl 3.2.0#15` in
[vcpkg-cache PR #215](https://github.com/qigao/vcpkg-cache/pull/215).
Existing production CNet consumers with an explicit `#13` pin remain
unchanged. This documentation does not switch any consumer.

The installed Crypto SDK exports neither `GmSSL::GmSSL` nor a second
GmSSL archive; its own public API remains in `include/crypto/` and the
approved direct SM3 header. License metadata is retained.

`tools/verify_vcpkg_gmssl.py` validates the complete accepted #14
port Git tree and installed static package. Do not silently extend that
pin to a future port revision: requalify first.
`tools/audit_static_crypto.py` validates the single archive and symbol
cardinality. C11/C++17, OpenSSL3 TLS1.2/1.3, HRR/CCS, X.509, and
Sanitizer tests remain available to run locally or in vcpkg-cache CI.
Crypto's automatic GitHub Actions workflows were removed intentionally.
