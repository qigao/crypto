# M3.2.1 — Independent OpenSSL 3 same-session TLS exporter oracle

This qualification follows the public Crypto TLS v1.2 peer/exporter
API in Draft #21. It tests the **opposite role** from the original
OpenSSL server interoperability gate:

- A separate, independently built installed C11 `Crypto::TLS`
  executable is the **real TCP/TLS server**. It has no GmSSL header
  or linker dependency; it imports only the one Crypto shared DSO.
- OpenSSL 3 `s_client` is the independent TLS client and native
  exporter implementation; the TLS 1.2 and TLS 1.3 client uses the
  same RSA leaf fixture and a trusted CA, with explicit cipher and
  signature algorithms.
- Both implementations derive
  `EXPORTER-Channel-Binding` (32 bytes) from the **same TLS session**.
  Since `openssl s_client -keymatexport` uses the *no context* form,
  the Crypto server calls `crypto_tls_session_export_v1_2(...,
  use_context=0)`. This test does not conflate the context-present
  TLS 1.2 RFC 9266 CNet binding variant; that is tested separately by
  two actual GmSSL peers with `use_context=1`.
- Each session additionally must deliver a genuine authenticated
  HTTP response from the Crypto C11 server to OpenSSL 3.

The server and OpenSSL3 client write raw exporter bytes to **only**
test-local `.secret` files; a cross-platform bounded subprocess
compares the exact 64-hex-character values and deletes them. Neither
exporter material nor the OpenSSL client secret diagnostic file is
printed or uploaded as a CI artifact. The server does not accept
external client connections except 127.0.0.1 and has a bounded
accept/TLS/receive/send lifecycle. Raw fixture private keys are test
temporary and excluded from upload.

This adds Linux/macOS OpenSSL 3 test and Linux sanitizer coverage
without modifying source-import provenance, the installed C11 API,
or the one-GmSSL-native-owner design. It does **not** imply
production CNet mTLS, system root trust, cross-DSO NativeIO BIO parity
or completed release governance.
