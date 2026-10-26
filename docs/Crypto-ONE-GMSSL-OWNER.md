# Crypto M2.2 — one physical GmSSL provider for SM3 and opaque TLS

**Status: Draft, qualification only. No vcpkg-cache/CNet production switch.**

This branch is stacked on Crypto Draft #16 and resolves the *structural*
duplication risk tracked by Crypto #17. It preserves the original C11
SM3 API of independent Draft #12, but **does not install #12's separate
`libcrypto_provider` shared binary**.

## Physical owner and public ABI

Exactly one shared image, `crypto_tls`, contains the **single** privately
assembled GmSSL 3.2 PIC implementation and both C11 interface sources:
`src/provider_sm3.c` and `src/crypto_tls_gmssl.c`. The original 92 source
objects, 40 historical source transformations and five separately verified
Crypto UB edits remain unchanged.

| CMake installed target | Type | Installed native image |
| --- | --- | --- |
| `Crypto::TLS` | imported SHARED | `crypto_tls` (one DLL/dylib/so) |
| `Crypto::Provider` | imported INTERFACE view | links `Crypto::TLS`, no new image |
| `Crypto::TLSHost` | host-side STATIC lease helper | only OS loader/atomic admission, no GmSSL |

The public <crypto/provider.h> ABI v0.1 and <crypto/tls.h> ABI v1 both
retain their distinct version marker semantics. One physical native owner
is not the same thing as treating the two API structures as identical.

The original v1 native export surface was 14 functions. The additive
v1.1 ALPN/inspection candidate now exports **exactly 18 public functions**:
three `crypto_provider_*`, eleven base `crypto_tls_*` and four v1.1
extension functions, all from the same physical shared binary. ELF uses separate SM3
and TLS linker version groups on the *same ELF image*, macOS one explicit
export list, Windows one explicit DLL export policy; private GmSSL
symbols are never exported.

Two installable configurations exist:
- `find_package(Crypto 0.1 CONFIG REQUIRED)` exposes
  `Crypto::Provider` as an imported INTERFACE view.
- `find_package(CryptoTLS 0.1 CONFIG REQUIRED)` exposes the exact
  same native `Crypto::TLS` and its host-only `Crypto::TLSHost`.
  `CryptoConfig.cmake` **requires** CryptoTLS and rejects an independent
  Provider native target. There is no `GmSSLConfig.cmake`, public
  GmSSL static archive or second Provider DLL in the install tree.

## Real installed and relocated acceptance

`tests/owner/` builds a fresh independent C11/C++17 project, links
BOTH public CMake views and executes:
1. SM3(abc) authoritative 32-byte digest; invalid inputs must not
   modify output; null-with-zero-size remains admitted.
2. Same-process TLS v1 runtime ABI check, creation and destruction.
   Genuine TLS 1.2/1.3 handshake/CA/SAN/provider lifetime remain in
   the inherited `tests/sdk` and OpenSSL3 peer qualification workflows.
3. Two separately loadable native MODULE images, each importing both
   API views; function pointer identity for SM3 and TLS must match
   between both plugins and the host over eight quiescent unload cycles.

The three-platform CI runs this from a clean installed SDK and then
**physically moves the prefix**, rebuilds the same standalone consumers
against the relocated prefix and repeats both runtime tests and the native
ELF/Mach-O/PE binary-import/export/SONAME audit.

The binary audit checks exactly 14 approved exports, the ONE native
Crypto owner dynamic import of each consumer/module and absence of a
second `gmssl` or `crypto_provider` native image. The audit is evidence
of this specific installed C11/C++17 consumer graph; it does not
magically prove arbitrary external plugins cannot embed their own
GmSSL static archive.

## Release boundaries

- The first physical shared owner is not permission to merge the
  superseded independent SM3 provider image in Draft #12.
- Crypto Draft #16 retains host-side lease and adversarial unload
  gates; this branch must not weaken those tests or switch CNet.
- [Crypto #18](https://github.com/qigao/crypto/issues/18) lists
  real CNet ALPN, certificate/trust, exporter, ShangMi/TLCP, and
  NativeIO parity gaps. [salts-core #20](https://github.com/qigao/salts-core/issues/20)
  separately governs shared foundation runtime owner identity.
- Release/pinning/registry changes are prohibited until both owner
  scopes, relocated installed SDK and consumers are qualified.
