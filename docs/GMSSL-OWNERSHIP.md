# Crypto is the sole owner of cryptographic code and GmSSL adaptations

**Source of truth:** [qigao/crypto](https://github.com/qigao/crypto).
All future cryptographic function implementation, algorithms, TLS/TLCP/DTLS,
X.509, provider hardening, tests and packaging changes happen in Crypto's
source tree and its pinned GmSSL assembly. Do not implement or patch those
functions in qigao/vcpkg-cache, Salts, SaltsUtils, CNet or other consumers.

The only native Crypto link target is **Salts::Crypto**, installed by
find_package(Crypto CONFIG REQUIRED). The installed package contains a single
STATIC archive. No provider DLL/DSO, public GmSSL::GmSSL target, alternate
SaltsCrypto/Crypto namespace, compatibility aliases, or source fallbacks.

## Completed baseline import

The original immutable vcpkg-cache GmSSL port git tree
8e8fda20b723803adc53613f6f608736238ac97d contributed **92 of 92**
nonpackaging file contents unchanged and byte-exact to
providers/gmssl/patches and providers/gmssl/tests. Upstream GmSSL 3.2 is
pinned at commit 7c9f02904ef33e59c87b4f16621cc8fd434e7579. The other
3 original vcpkg port files were packaging-only; they are **not**
cryptographic implementations and must not be imported as a second SDK.

## Additional review: former vcpkg-cache Draft #209

The original TLS 1.3 middlebox compatibility CCS and HRR-padding changes
were only a Draft in the old vcpkg-cache repository, not published as a
qualified Crypto ABI. This candidate imports exactly **7 source/test files**
from that Draft's head 59693dfdb4e6830df838edf9da109f855fd2ea24 under
providers/gmssl/candidates/port14, with the original Git blob identities.

The candidate is intentionally **not part of the installed Salts::Crypto
archive**, its source patch replay, or public ABI. Three-OS independent
C11 parser tests and exact immutable source audits allow evaluation without
silently combining a port14 TLS_CONNECT layout with the existing static
Crypto source. Next, adapt the incremental candidate into Crypto-owned
GmSSL hardening, then independently qualify TLS1.2/TLS1.3 including
default OpenSSL X25519/HRR+CCS, mTLS, CA/SAN fail-closed, corrupt/duplicate
CCS, padding negatives, source ASan/UBSan/LSan+TSan, C11/C++17 installed
static SDK and dependent CNet owners at one exact HEAD. Only after this
may the candidate be admitted and its staging source retired. Neither
this candidate import nor the original #209 authorizes the old vcpkg
port14 registry version, a production CNet switch or a new API.

## Retirement of the vcpkg port

qigao/vcpkg-cache should own only generic package/tool infrastructure.
The ports/gmssl cryptographic source and its custom-registry ownership are
proposed for deletion in a separately gated migration PR. Keep that
deletion Draft until all pinned downstream clients use the installed
Crypto package. Retain historical Git commits for provenance; do not
recreate a forwarding GmSSL::GmSSL package or compatibility alias.

No two live GmSSL owners; no fallback; fail fast on unqualified inputs.
