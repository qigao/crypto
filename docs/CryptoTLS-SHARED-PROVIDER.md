# Crypto M1.5: first single shared native TLS provider (Draft)

The pinned, reproducibly assembled GmSSL 3.2.0 implementation is linked **once**
inside `Salts::TLS`, a shared library. Production CNet and the existing
`vcpkg-cache gmssl 3.2.0#13` port are unchanged.

## Boundaries

- `include/crypto/tls.h` is a pure C11, versioned public interface.
  Neither downstream clients nor `CryptoTLSTargets.cmake` include or link
  any `gmssl/**` headers or static libraries.
- `src/crypto_tls_gmssl.c` is the only native backend adapter. GmSSL owns
  certificate parsing and authentication, TLS cryptography and record/alert
  processing. The adapter exposes no raw `TLS_CTX`, `TLS_CONNECT`,
  `tls_ret_t`, static private symbols or borrowed backend handles.
- `cmake/crypto_tls.elf.map` (ELF) and the macOS export list restrict
  dynamic exports to the eleven reviewed `crypto_tls_*` functions;
  Windows exports only explicit `CRYPTO_TLS_API` entrypoints. The private
  PIC `libgmssl.a` is not installed and must never be linked by another
  downstream DSO.
- TLS 1.2 ECDHE-RSA and TLS 1.3 RSA-PSS (AES-128-GCM, P-256 key share)
  are first qualification profiles, **not a comprehensive cipher policy**.
  Exactly one explicit CA file and hostname is required for clients.
  Absence of either is a hard error, not a system-trust or OpenSSL fallback.
  Hostname/SAN and certificate verification are performed by GmSSL.
- The external-I/O transport is borrowed and nonblocking: `write/read`
  callbacks return 1..len bytes, 0 EOF, -1 AGAIN or -2 fatal. The provider
  owns no sockets and closes none. Short I/O, `AGAIN`, TLS shutdown and
  repeated creation/destruction are checked by an *installed C11 consumer*.

## Lifetime contract / intentionally incomplete areas

- Provider remains allocated until every session has been explicitly destroyed.
  `crypto_tls_provider_destroy()` returns BUSY without consuming its pointer
  otherwise.
- One thread drives one session at a time. Overlap returns BUSY.
  `crypto_tls_session_cancel()` only publishes an atomic cancellation bit.
  It never frees callback user memory, a transport buffer or TLS state.
  `crypto_tls_session_destroy()` returns BUSY while a drive call is active.
- Caller must guarantee that session/provider handles remain live through
  concurrent method entry, and must synchronize terminal destruction after
  all callers have quiesced. **Cancellation does not make an arbitrary
  dangling pointer safe.**
- The existing provider lifetime contract **does not** yet guarantee safe
  concurrent DSO unloading after one thread has begun but not acquired a
  session lease. The host is responsible for `dlclose` after all sessions
  and callbacks return. Dedicated concurrent close/cancel/DSO and TSan tests
  remain future gates.
- The DLL/so/dylib is a qualification candidate, not an ABI-stable product
  release. No auto provider discovery, multi-provider hot swap, production
  TLS trust-policy setter, session resumption, native event-loop owner,
  public `tls_export_keying_material` or DTLS is claimed.
- No C++ runtime or external Salts/CMeta/CFlow dependency is required
  for this minimal C11 provider.

## Installed SDK verification

The CI workflow `crypto-shared-provider-sdk.yml` rebuilds the exact
upstream revision, applies the 40 original transformations and five
separate Crypto safety fixes, compiles its private static code and
installs **only** the shared `Salts::TLS` package + public header.

A second, independently configured C11 CMake project reads only the installed
package and runs:

1. TLS 1.2 + 1.3 real client/server handshake, application-data and
   `close_notify` over independently bounded in-memory transports.
2. Denial of invalid/missing CA and wrong ABI requests, provider BUSY
   while sessions are alive, cancellation before handshake.
3. Repeated standalone runtime `dlopen/LoadLibrary` and unload, checked
   public API symbols, and rejection of backend TLS/X.509 exports.
4. On Linux, `nm -D` checks that no unreviewed backend symbol is exported.

A passing install/build is **not** a substitute for independent OpenSSL,
source ASan/UBSan/LSan/TSan or actual shutdown-vs-cancel concurrency tests.
The prior 29 original tests and original independent OpenSSL interop continue
to be separately enforced.

Tracking: [Crypto #2](https://github.com/qigao/crypto/issues/2).
