# Canonical static Crypto ownership

```text
qigao/vcpkg-cache/ports/gmssl (source, patches, versions, static package)
                |
      installed vcpkg GmSSL archive and headers
                |
        qigao/crypto private build input
          + C11 TLS/CipherBIO facade
          + Crypto SHA256 and Ed448 adapters
          + private libecc Ed448-only objects
          + OS-backed CSPRNG
                |
      one native installed static archive
                |
            Salts::Crypto
```

The only public package target is `Salts::Crypto`. Internally,
`GmSSL::GmSSL` is imported solely from a verified vcpkg installation.
The installed SDK does not export a GmSSL library, split Crypto target,
dynamic Provider/Host, compatibility alias or duplicated algorithm source.

`tools/verify_vcpkg_gmssl.py` checks the complete 97-file pinned port
Git tree, source metadata and installed static package, and
`tools/audit_static_crypto.py` checks archive/header/symbol ownership.
Neither invokes an automatic GitHub Actions workflow. The build and
conformance tests remain runnable locally.

GmSSL security fixes and their source sanitizers belong in vcpkg-cache,
not in a revived `providers/gmssl` directory. Historical port #13
remains available for production CNet consumers with a fixed pin.
