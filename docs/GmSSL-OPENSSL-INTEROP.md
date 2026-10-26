# M1.3 — native GmSSL 3.2 vs independent OpenSSL 3 peers

This is an additional **qualification-only** layer stacked on the unchanged
original 29-test matrix. It does not change the original 92 imported source
objects, the 40 transformations, GmSSL source code, or any vcpkg registry.

The patched original `gmssl-bin` CLI is built from the same exact source
checkout and private GmSSL implementation as the C11 tests. On Linux/macOS
the CI runner then invokes two *unchanged original* provider contracts:

1. `tls12-rsa-mtls-interop.sh`: independent OpenSSL 3 RSA certificates,
   GmSSL TLS 1.2 server vs OpenSSL client with client certificate, then
   GmSSL TLS 1.2 client vs OpenSSL mTLS server. Both directions require
   authenticated application-data / HTTP evidence.
2. `tls-p384-issuer-interop.sh`: OpenSSL 3 generates a P-384 issuing CA
   and a P-256 server leaf with SHA-384 issuer signature, verifies the
   fixture independently, and serves TLS 1.2 + TLS 1.3 to a GmSSL client.
   Both versions require exact negotiated TLS version/cipher and a
   successful authenticated HTTP response, while wrong CA and wrong
   hostname/SAN must fail without application-data success.

The Python wrapper `tools/run_gmssl_openssl_interop.py` rejects a missing
CLI or anything other than OpenSSL 3, bounds both complete process groups,
disallows retries/xfails and writes a machine-readable result receipt. Generated
private test keys remain in disposable scratch directories. The CI artifact
contains only a result receipt and stdout/stderr diagnostics.

On macOS, CI explicitly prepends Homebrew OpenSSL 3 to `PATH` instead
of inadvertently using system LibreSSL. Windows retains the 29 compiled
C11 contracts; these Bash network peer scripts are not yet qualified there.

**Source ownership:** the Crypto repo owns the test invocation, receipt and
test-only source assembly; the two original test scripts remain frozen in
`providers/gmssl/tests`. An OpenSSL CLI is an independent *test oracle and
peer only*, never a production TLS fallback. Neither a public shared Crypto
Provider, installed C11 ABI, sanitizer/DSO-unload gate nor production CNet
migration is established by passing these tests.

Tracking: [Crypto #2](https://github.com/qigao/crypto/issues/2).
