# M1.3 — independent OpenSSL TLS/X509 peer qualification

This staged Draft does **not** claim a shared Crypto Provider ABI or an
installed SDK. It assembles the unchanged GmSSL 3.2.0#13 sources using
the pinned original 40 patches, compiles the real original \`gmssl\` CLI,
and tests it against **separate live OpenSSL 3 processes**.

On Linux and macOS:

1. The exact original RSA mTLS script runs GmSSL TLS 1.2 server with
   OpenSSL client **and** GmSSL TLS 1.2 client with OpenSSL server;
   generates fresh CA, server and client certificates on the runner,
   with client-authentication enabled and verified. No loopback-
   same-provider success is substituted for true interop.
2. The original P-384-issuer script generates a fresh OpenSSL P-384
   issuing CA, a P-256 leaf signed by ECDSA/SHA384, verifies the CA/EKU
   and DNS:localhost identity in OpenSSL, then runs TLS 1.2 and 1.3
   using **GmSSL client vs OpenSSL server**. It also requires actual
   GmSSL rejection of an untrusted CA and wrong hostname, rather than
   trusting the GmSSL CLI process exit status alone.
3. OpenSSL 3 is mandatory; macOS uses Homebrew OpenSSL 3, never a
   potentially incompatible default LibreSSL wrapper. Source SHA and
   patch receipt are retained; upload **only logs**, not test private
   CA/server/client keys.

All shell scenarios execute the original bytes imported from
vcpkg-cache; no provider API shim or new OpenSSL fallback implementation
is linked into GmSSL or Crypto. When this PR is green, the independent
peer paths have a bounded two-OS qualification; still pending before
release are Linux and Windows native sanitized source/DSO lifecycle,
opaque C11 Crypto provider entry points, one shared binary owner,
and full CNet application cutover. Old \`gmssl 3.2.0#13\` in vcpkg-cache
and production CNet remain untouched.
