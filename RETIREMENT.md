# qigao/crypto retirement gate

**Target:** qigao/salts-core, with independent `asn1/` and `crypto/`
source subdirectories, root assembly, and canonical exported
`Salts::ASN1` and sole `Salts::Crypto` targets.

**Source provenance:** `qigao/crypto/master`
`57e03d9ebefc3b9348764edaddb834862e669a45`; mTLS Draft PR #43
`0b4ee094ce8002e6169ce231028107eba63588c6`.
The 18 changed PR43 inputs were brought into SaltsCore migration Draft #75,
with 17 Git-identical blobs and one module checker adapted to the new root.
The original mTLS CI workflow is retained as historical test input;
do not count its old GmSSL build as a native TLS implementation.

**Exit gate to archive:**
- Exact source and test preservation (all 18 PR43 inputs, ABI, Python peers).
- SaltsCore ASN1/Crypto local CMake with installed C11 and C++17 tests.
- No active source consumers, release workflows, vcpkg pin or CI download
  remaining against this separate qigao/crypto GitHub repository.
- Native TLS/TLCP inside one Salts::Crypto: no third-party TLS engine
  including GmSSL. Retain original TLS1.2/1.3, TLCP, ShangMi, mTLS,
  CA/SAN, ALPN, exporter, close/EOF/fatal alert and real IOCP semantics.
- All exact-head cross-platform tests, sanitizers, plugin physical owner
  and downstream CNet tests pass. No fallback or missing APIs.
- Retire open implementation branches/PRs only after their source and tests
  are accepted in SaltsCore. Leave historical issues available for audit.

Once complete, **archive this repository read-only through GitHub Settings**.
Do not delete it or archive before missing source/tests are recovered.

Tracking issue: https://github.com/qigao/crypto/issues/45
New source PR: https://github.com/qigao/salts-core/pull/75
