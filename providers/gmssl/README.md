# GmSSL source ownership in qigao/crypto

This is the **current** GmSSL integration contract. Crypto owns the patched
GmSSL 3.2 source extensions and publishes exactly **one**
`Salts::Crypto` static archive (via `find_package(Crypto 0.1 CONFIG REQUIRED)`).
The pinned upstream GmSSL archive is a private *build input*, never a second
installed package, shared Provider, exported CMake target or runtime fallback.

## Active source layout

| Path | Purpose |
| --- | --- |
| `src/*.c` | 6 actual imported C source/backport implementations |
| `include/gmssl/*.h` | 7 imported GmSSL private/build overlay headers |
| `patches/*.cmake` and `patches/*.patch` | 40 immutable historical source adaptations, **no C implementations or headers** |
| `hardening/` | Post-import reviewed Crypto-only source hardening |
| `diagnostics/` | Opt-in qualification instrumentation |
| `tests/` | Original GmSSL C11/TLS/X.509 conformance tests and fixture files |
| `provenance/` | Historical, immutable source identification and import evidence |

`tools/verify_gmssl_import.py` checks the original **92 source/test/patch
Git blobs** against `provenance/ownership-manifest.json` and `patch-order.json`.
The original 95-entry deterministic handoff archive retains its original
entry names and SHA-256 even though the live source files have moved.

The historical handoff README is preserved **byte-for-byte**, at
`provenance/HISTORICAL-HANDOFF.md`. Its statements about this repository not
existing were true only at the time of the original handoff; they are not
the current project status. The immutable historical manifest is likewise an
origin record, *not* a current path inventory.

## Build/consume

1. Check out the exact pinned upstream
   `guanzhi/GmSSL@7c9f02904ef33e59c87b4f16621cc8fd434e7579`.
2. Run `python3 tools/verify_gmssl_import.py`; apply original immutable
   adaptations via `cmake -DGMSSL_UPSTREAM_SOURCE=<checkout> -P tools/assemble_gmssl.cmake`.
   Source assembly reconstructs the historical `CMAKE_CURRENT_LIST_DIR`
   sibling layout in a temporary staging directory and cleans it afterward.
   No active duplicate of the 13 backport sources lives in `patches/`.
3. Build upstream `gmssl` as a **private static PIC input**, then build
   and install Crypto using `CRYPTO_GMSSL_SOURCE` and `CRYPTO_GMSSL_STATIC`.
   Consumers find/link only `Salts::Crypto`.

Installed consumers of SM3 can include `<gmssl/sm3.h>` and call the real
`sm3_init`, `sm3_update` and `sm3_finish` from that archive. There is
**no** `<crypto/provider.h>`, `Crypto::` alias or SM3 forwarding trampoline.
Other GmSSL implementation headers are *not* automatically published; expand
the installed header set only with an ABI/Installed SDK qualification.

## Status and independent work

The static Crypto SDK, original source and runtime TLS tests were qualified on
the exact HEAD of [Crypto PR #32](https://github.com/qigao/crypto/pull/32).
That Draft is stacked on [#30](https://github.com/qigao/crypto/pull/30).
Opt-in CCS/HRR candidate work is isolated in [#28](https://github.com/qigao/crypto/pull/28);
do not silently integrate candidate or change TLS behavior.

This source/layout cleanup does **not** publish a new Crypto SDK, retire the
vcpkg-cache `gmssl 3.2.0#13` port, or switch production CNet.
