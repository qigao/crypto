# M2.1 — single shared Crypto Provider 0.1 (SM3 only)

This branch introduces the first actual **Crypto-owned native SHARED** binary,
not a source-only/temporary static GmSSL consumer. Its exact input is
\`guanzhi/GmSSL@7c9f02904ef33e59c87b4f16621cc8fd434e7579\`,
the 40 original GmSSL 3.2.0#13 source adaptations and the **five**
UB fixes already qualified against original C11 tests and independent
OpenSSL peers in staged Draft PRs #7/#9.

The implementation compiles PIC \`libgmssl.a\` only as a **private**
dependency into \`Crypto::Provider\`. The installed package publishes
only:
- \`crypto_provider_abi_0_1_required()\` exact ABI 0.1 link marker;
- \`crypto_provider_runtime_abi()\` returning 0x00000100;
- bounded one-shot \`crypto_provider_sm3()\`, with RFC-style SM3 \`abc\`
  known-answer digest \`66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\`.

The public header \`include/crypto/provider.h\` exposes **no** TLS_CTX,
TLS_CONNECT, SM3_CTX or other provider-internal GmSSL types; inputs
are temporary borrowed slices, outputs are caller-owned 32 bytes,
and failed calls cannot mutate output. SM3 state is erased locally
after each call. The provider owns the only private GmSSL code image.

### Native ABI and export policy

- Linux: native SONAME \`libcrypto_provider.so.0.1\` and an explicit
  ELF version script hiding every \`gmssl_*\`, \`sm3_*\` and TLS symbol.
- macOS: \`@rpath/libcrypto_provider.0.1.dylib\` plus an explicit
  three-symbol export list; never export upstream GmSSL.
- Windows: \`crypto_provider-0.1.dll\` and versioned import library,
  with only three \`__declspec(dllexport)\` APIs.
- CMake: installed \`CryptoConfig.cmake\` + \`CryptoTargets.cmake\`,
  pre-stable \`SameMinorVersion\` package policy, imported
  \`Crypto::Provider\` is SHARED, never STATIC or an alias to GmSSL.

### Qualification

A three-platform workflow independently compiles the provider and
**clean-install C11/C++17** consumers. Each checks the exact ABI 0.1
marker and SM3 known-answer; negative inputs must preserve output.
Two separate test MODULEs each call the provider, return the ABI
marker's native function pointer, and prove it matches the same
loaded provider binary across eight safe load/unload cycles.
The modules must be quiescent before unloading; concurrent force
unload of running callbacks is **not** claimed.

After tests and final ELF/Mach-O/PE exports/imports auditing, the SDK
installation is physically **moved**; fresh external consumers and
two MODULEs are rebuilt and retested, with exact native 0.1 identity
and no source-built/static fallback. Export audit must see **exactly
the three public Crypto APIs**, and no old GmSSL symbols or dynamic
GmSSL dependency. Signed source/UB receipts are preserved separately.

### Not yet supported

This is **only a single-owner SM3 foundation**, not a TLS 1.2/1.3,
X.509 CA/SAN or Ed448 public Crypto ABI, and is not yet a full GmSSL
runtime's owner across all TLS consumers. Opaque TLS provider/session
state, certificate policy, failure/cancel/concurrent DSO unload,
process-wide TLS lifetime, FIPS/security review, full native Sanitizer
matrix, signed/immutable install provenance and release/rollback remain
future gates. Production CNet/Salts, and historical
\`vcpkg-cache gmssl 3.2.0#13\`, remain **untouched**.
