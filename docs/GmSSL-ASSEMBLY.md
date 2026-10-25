# M1.1 — assemble the pinned GmSSL 3.2 source independently

The first source assembly candidate is **not a published Crypto provider**.
It replays the exact 40 source transformations that were previously embedded
in vcpkg-cache `gmssl 3.2.0#13`, using the original Git commit
`guanzhi/GmSSL@7c9f02904ef33e59c87b4f16621cc8fd434e7579`.

Run in a clean external checkout:

```bash
cmake -DGMSSL_UPSTREAM_SOURCE=/path/to/pristine/GmSSL \
      -DGMSSL_ASSEMBLY_RECEIPT=/tmp/assembly.json \
      -P tools/assemble_gmssl.cmake
```

The assembler checks the source revision and clean Git checkout,
applies the P-256 DER patch with `git apply --check`, then includes the
39 historical CMake source adaptations **in the attested original order**,
with a strict local `vcpkg_replace_string` implementation. It preserves
the static GmSSL implementation configuration, feature macros and explicit
source ownership, but does not import `portfile.cmake`, `vcpkg.json` or
`GmSSLConfig.cmake` into Crypto.

A first Linux CI job compiles the patched static implementation with
`-fPIC` and runs five original C11 ABI/crypto/X.509 contracts against
it. The test-local CMake imported target is used **only inside this
qualification project**, not exported as a public dependency.

**Status boundaries:** static `libgmssl.a` is currently an intermediate
for independent source qualification; never link it into multiple
production DSOs. This milestone does **not yet build** a single shared
`CryptoProvider` image or expose an opaque public C11 TLS API.
TLS 1.2/1.3 end-to-end, real OpenSSL interoperability, all 39 contract
tests, P-384 trust chain validation, lifecycle and ASan/UBSan/TSan are
future required gates before moving the vcpkg port or switching CNet.

Tracking: [Crypto #2](https://github.com/qigao/crypto/issues/2) and
[vcpkg-cache #207](https://github.com/qigao/vcpkg-cache/issues/207).
