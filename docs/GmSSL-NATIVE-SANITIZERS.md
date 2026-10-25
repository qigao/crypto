# M1.4 — instrument original patched GmSSL 3.2 source under sanitizers

This Draft qualification uses the same immutable original upstream SHA
`7c9f02904ef33e59c87b4f16621cc8fd434e7579`, the verified 92
migrated Git blobs, and the same 40 source modifications as M1.1–M1.3.

On Ubuntu 24.04 it builds **both the actual private GmSSL C sources and
the unmodified original contract executables** using
`-fsanitize=address,undefined -fno-omit-frame-pointer -g`. Simply adding
sanitizers to executables linked against an unsanitized static lib is not
sufficient. It checks all 29 original C11 TLS/X.509 contracts, then builds
and invokes the original GmSSL CLI against independent OpenSSL 3 peer
scripts, keeping the same CA/SAN and authenticated-message assertions.

The workflow enables ASan leak detection and fail-on-error, UBSan
fail-on-error with stack traces, and an explicit LeakSanitizer error exit
code. No sanitizer suppressions, retries, disabled tests, runtime fallbacks,
or replacement TLS libraries are permitted.

This is **not a production shared Provider** and does not yet prove
concurrent cancellation or DSO unload. A separate real multi-session,
cancellation-versus-close and provider lifetime test suite with TSan is
required before publishing a versioned C11 ABI, installing SDK consumers,
modifying vcpkg-cache or switching production CNet.

Tracking: [Crypto #2](https://github.com/qigao/crypto/issues/2).
