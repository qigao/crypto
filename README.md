# Crypto — native C11 provider platform (bootstrap)

This repository is the intended owner of the native cryptography and TLS
provider implementation used by SaltsCore, CNet and other consumers.

**Current phase: provider-source migration, NOT a released Crypto ABI.**
The historical GmSSL `3.2.0#13` source adaptations and test corpus are
being imported from [qigao/vcpkg-cache](https://github.com/qigao/vcpkg-cache)
under a provenance-locked Draft PR. Its vcpkg registry tree and
production consumers remain unchanged until the standalone provider is
assembled, independently qualified and installed.

Planned boundaries:

- Crypto controls cryptographic primitives, opaque TLS/X.509 provider
  sessions, identity and failure/cancellation/DSO lifetime contracts.
- `vcpkg-cache` controls provider packaging, registry versions, cache
  metadata and package-consumer build verification.
- Salts/CNet consume the Crypto provider through one binary owner,
  **never** embedding duplicate GmSSL state in another module.

See [vcpkg-cache #207](https://github.com/qigao/vcpkg-cache/issues/207)
and [staged source kit PR #208](https://github.com/qigao/vcpkg-cache/pull/208).
