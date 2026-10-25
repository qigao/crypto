# M1.4 — ASan/UBSan/LeakSanitizer and TSan, original 29-source tests

This Draft builds the **actual full GmSSL 3.2.0 source** at immutable
upstream SHA with exactly 40 original source adaptations. Both native
\`libgmssl.a\` and the same **29 unchanged original GmSSL contract test
sources** compile under the same sanitizer configuration:

- Linux \`-fsanitize=address,undefined\` with LeakSanitizer enabled,
  abort-on-error and no suppression.
- Independent Linux \`-fsanitize=thread\` with fail-on-race and no
  suppression.

The source suite includes TLS 1.2/1.3 in-memory External I/O handshakes,
ALPN, TLS version range, X.509 CA/EKU/Basic Constraints, P-384/SHA384,
P-256 DER and RSA private/public/PKCS#8 operations. CI asserts that all
**29 original CTests are registered** and repeats every case three
times without XFAIL, skipped assertions or a non-instrumented library.

The compiled static GmSSL here is an **internal source qualification
target only**, not the production shared CryptoProvider or a license
to embed GmSSL into multiple consumer DSOs. Separate work must qualify
a single state-owning shared Crypto Provider, true OpenSSL 3 peer
interoperability, cancellation/close and DSO quiescence before the
vcpkg-cache 3.2.0#13 port or CNet may change.
