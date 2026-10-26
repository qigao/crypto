# GmSSL source import status (not a released Crypto provider)

The independent `qigao/crypto` repository now owns an **exact imported
source/test copy** of the historical GmSSL vcpkg-cache overlay files.
These files preserve their original Git Blob identities. The accompanying
`ownership-manifest.json` is retained byte-for-byte from when the
destination repository had not yet been created; its historical
`repository_exists: false` field is an origin snapshot, not the
current repo state. This document records the subsequent import.

- Original package: `gmssl 3.2.0#13`
- Original vcpkg port Git Tree: `8e8fda20b723803adc53613f6f608736238ac97d`
- Original GmSSL source: `guanzhi/GmSSL@7c9f02904ef33e59c87b4f16621cc8fd434e7579`
- Source archive SHA-256: `586bbee98e7a6ba83ab13549d369d01fc341788ab3c53be5372d2bc063da4601`
- Contents: 40 source patches (including first upstream patch), 13
  original custom C/header/backport files, 39 independent contract
  tests and fixtures, plus original README/license/provenance.
- Packaging files not imported: `vcpkg.json`, `portfile.cmake`,
  `GmSSLConfig.cmake`; they remain owned by vcpkg-cache.

**Not yet completed:** assembling a validated patched GmSSL 3.2
implementation or fork, compiling a standalone Crypto GmSSL Provider,
public C11 opaque TLS interface, ABI epoch, native installed SDK,
X.509/TLS real interoperability or native sanitizer qualification.
The source files and `vcpkg_replace_string` patch scripts are
not, by themselves, an independently buildable Crypto library.

Do not change production CNet or the frozen vcpkg-cache `3.2.0#13`
port until those gates pass. Follow
[vcpkg-cache #207](https://github.com/qigao/vcpkg-cache/issues/207)
and [source handoff PR #208](https://github.com/qigao/vcpkg-cache/pull/208).
