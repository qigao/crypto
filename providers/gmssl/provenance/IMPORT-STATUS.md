# GmSSL owner / migration status

**Active repository:** [qigao/crypto](https://github.com/qigao/crypto),
single installed `Salts::Crypto` static archive and target.

- Frozen upstream: `guanzhi/GmSSL@7c9f02904ef33e59c87b4f16621cc8fd434e7579`
- Historical vcpkg-cache port: `gmssl 3.2.0#13` (production pin unchanged)
- Original registry Git tree: `8e8fda20b723803adc53613f6f608736238ac97d`
- Immutable 95-entry handoff archive SHA-256:
  `586bbee98e7a6ba83ab13549d369d01fc341788ab3c53be5372d2bc063da4601`
- Immutable import payload: 40 original source patches, 13 original C/header
  source backports, 39 original contract files, with licenses/metadata.

**Completed in Draft #32:** 13 source/header blobs moved to
`providers/gmssl/src` / `providers/gmssl/include/gmssl`, retaining Git
identity; only actual patch scripts remain in `patches/`. Source assembly
uses private temporary layout staging. The generic `crypto/provider.h`
SM3 trampoline is deleted, and the installed SDK exposes direct
`gmssl/sm3.h` from the same `Salts::Crypto` static image.

**Qualification evidence, exact #32 HEAD `30351113`:**

- [Static installed SDK #40375231113](https://github.com/qigao/crypto/actions/runs/40375231113): **7/7**
  Linux, macOS, Windows, Android ARM64, iOS ARM64, ASan/UBSan/LSan and TSan.
- [Original source assembly #40375231115](https://github.com/qigao/crypto/actions/runs/40375231115): **3/3**
- [Git-blob and historical archive provenance #40375231168](https://github.com/qigao/crypto/actions/runs/40375231168): **3/3**
- [GmSSL native sanitizer contracts #40375231147](https://github.com/qigao/crypto/actions/runs/40375231147): **1/1**

This file describes the migration **state**, whereas
`ownership-manifest.json`, `patch-order.json` and
`HISTORICAL-HANDOFF.md` are frozen provenance source records. Do not
rewrite those frozen inputs just to refresh narrative documentation.

**Not implied:** production CNet TLS cutover, GmSSL port retirement,
release publication, automatic acceptance of pending CCS/HRR #28, or
any new dynamic Provider/alias. Finish the review/merge gates for
stacked Draft #30/#32 before treating master as migrated.
