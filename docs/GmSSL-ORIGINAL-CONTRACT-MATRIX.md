# Extended 29-source GmSSL original C11 contract matrix

Stacked Draft qualification on the exact accepted Crypto GmSSL 3.2
source-assembler, not a separate GmSSL rewrite or Crypto ABI publication.

The original upstream source and unchanged 40 transformations first
produce \`libgmssl.a\` inside an isolated build. The independent CMake
qualification project then compiles and runs **29 unchanged original
GmSSL 3.2 contract test sources**, including:

- SHA-1/DES historical compatibility only as private provider tests;
- TLS 1.2 ALPN, TLS protocol version admission and client/server dispatch;
- RSA verification, signatures, private operations and PKCS#8;
- TLS 1.3 RSA-PSS, exporter, inspection and certificate capacity;
- X.509 CA/EKU, Basic Constraints, P-384/SHA384 and P-256 DER;
- real original in-memory TLS 1.2 and TLS 1.3 External I/O handshake,
  callbacks, closure and error paths.

The workflow requires **all 29 CTest cases to be registered** before
execution and fails on any compile, runtime, or test assertion failure.
The original source test files and fixtures are unchanged; only an
independent test-target list is added.

This is source-level GmSSL qualification. It does not constitute a
published Crypto Provider ABI, independent OpenSSL network handshake,
single process-wide shared owner, full sanitizer qualification or
port/CNet migration. Keep this PR Draft/unmerged until all gates pass.
