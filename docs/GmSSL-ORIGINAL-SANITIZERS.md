# M1.4 — ASan/UBSan/LeakSanitizer and TSan, original 29-source tests

This Draft builds the **actual full GmSSL 3.2.0 source** at immutable
upstream SHA with exactly 40 original source adaptations. Both native
\`libgmssl.a\` and the same **29 unchanged original GmSSL contract test
sources** compile under the same sanitizer configuration:

- Linux \`-fsanitize=address,undefined\` with LeakSanitizer enabled,
  abort-on-error and no suppression.
- Independent Linux \`-fsanitize=thread\` with fail-on-race and no
  suppression.

The source suite includes TLS 1.2/1.3 in-memory External I/O handshakes,
ALPN, TLS version range, X.509 CA/EKU/Basic Constraints, P-384/SHA384,
P-256 DER and RSA private/public/PKCS#8 operations. CI asserts that all
**29 original CTests are registered** and repeats every case three
times without XFAIL, skipped assertions or a non-instrumented library.

The compiled static GmSSL here is an **internal source qualification
target only**, not the production shared CryptoProvider or a license
to embed GmSSL into multiple consumer DSOs. Separate work must qualify
a single state-owning shared Crypto Provider, true OpenSSL 3 peer
interoperability, cancellation/close and DSO quiescence before the
vcpkg-cache 3.2.0#13 port or CNet may change.


## M1.4 discovered native undefined behavior — no sanitizer suppression

The original 29-contract sanitizer matrix found **three independent C
undefined behavior contracts** in the source currently assembled by the
historic vcpkg port. Two 32-bit finite-field half operations computed the
high carry bit as signed \`(c & 1) << 31\` in secp256r1.c and the P-384
verifier backport secp384r1.c. The TLS 1.2 ServerHello decoder called
\`memcpy(dst, NULL, 0)\` when an empty Session ID was valid. Non-sanitized
source tests and independent OpenSSL interoperability passed; UBSan
correctly rejected these operations.

The additive, fail-closed **Crypto-only candidate** source patch at
\`tools/qualification_patches/gmssl-ub-fixes.cmake\` fixes:
- P-256/P-384: explicitly cast the carry to \`uint32_t\` before the
  31-bit shift, keeping limb arithmetic unsigned.
- TLS 1.2: validate Session ID length against the destination and
  a required non-NULL source for nonzero lengths; do not call memcpy
  for an empty ID.

Every patch must match exactly one pinned source anchor. CI stores
a new post-patch SHA-256 receipt for the three changed source files;
the **40 original GmSSL patches and 92 imported Git blobs are not
modified**, and the old vcpkg-cache \`3.2.0#13\` port stays frozen.
The full **29×3 original source suite** must still pass under both
ASan/UBSan/LeakSanitizer and TSan with fail-on-diagnostic, no suppressions.

This is native source hardening of a candidate, not a Crypto Provider
release, and the safety changes still need the separate real OpenSSL
peer regression after incorporation into the eventual reviewed provider.


### Additional TLS 1.3 empty legacy Session ID

The next fail-closed ASan/UBSan run exposed a fourth genuine source
defect in \`tls13_recv_server_hello()\`: the upstream code called
\`memcmp(NULL, session_id, 0)\` when the peer echoed an empty TLS 1.3
legacy Session ID. The Crypto-only source adaptation now validates the
echo size and pointer for nonempty values and performs the byte
comparison *only* when its admitted length is nonzero. The TLS 1.3
handshake test must still complete, including the original callback
and failure paths.

The source receipt now records **four** exact single-anchor repairs,
including the SHA-256 of the patched \`src/tls13.c\`. All 29 original
source tests remain enabled × 3 repetitions under ASan/UBSan/LSan and
TSan; none is XFAILed or disabled. Original upstream/port input bytes
and the \`vcpkg-cache 3.2.0#13\` package remain unchanged.


### TLS 1.3 includes TWO separate legacy echo guards

The source preflight correctly rejected a proposed *single-site*
\`memcmp(NULL, session_id, 0)\` fix: the original GmSSL TLS 1.3 state
machine contains the same legacy Session ID check in both
\`tls13_recv_hello_retry_request()\` **and**
\`tls13_recv_server_hello()\`. The Crypto candidate now replaces
the identical unsafe code at **exactly two** matching locations,
verifies the match count first, preserves size and nonempty-source
validation, and rejects any unexpected source drift.

The receipt distinguishes **five UB source sites across four files**
(P-256 carry, P-384 carry, TLS 1.2 empty session ID, and both TLS
1.3 HelloRetryRequest and ServerHello empty legacy session ID
checks). Both original TLS 1.3 cases remain enabled; no sanitizer
suppression or unqualified skip.
