# Hardened native source → independent OpenSSL 3 interoperability

This qualification follows the fully instrumented GmSSL 3.2.0 source
candidate with **five exact UB sites corrected across four original source
files**, as qualified by Crypto Draft #7 (Linux ASan/UBSan/LeakSanitizer
and TSan, 29 original C11 source tests ×3 per instrumented build).

The workflow checks out the exact GmSSL upstream SHA
`7c9f02904ef33e59c87b4f16621cc8fd434e7579`,
applies the frozen **40 historical source transformations**, then
executes **Crypto-only** source corrections with an audited receipt:
P-256 and P-384 carry shifts, TLS 1.2 empty Session ID copy, and
TLS 1.3 empty legacy Session ID comparison in **both** HelloRetryRequest
and ServerHello. All five exact source sites must be recorded.

The same unchanged original OpenSSL-interoperability scripts that
passed prior to hardening are rerun against this corrected GmSSL native
binary with **separate OpenSSL 3 peers** on Linux and macOS:

- TLS 1.2 RSA mutual TLS: GmSSL server ↔ OpenSSL client and reverse.
- TLS 1.2/1.3 OpenSSL-generated P-384 CA/P-256 leaf ECDSA-SHA384,
  OpenSSL certificate oracle, and **negative** CA/hostname rejection.

Only evidence receipts and nonsecret logs are uploaded; generated private
key materials remain in ephemeral runner storage.

A green workflow proves that these five native safety corrections
preserve the specified independent peer behaviors, not that a shared
Crypto Provider, its public C11/TLS ABI, single binary owner or native
DSO unload/cancellation contract has been finished. The original
vcpkg-cache GmSSL 3.2.0#13 and production CNet remain unchanged.
