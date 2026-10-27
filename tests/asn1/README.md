# Crypto-specific ASN.1 key formats

This directory tests only ECDSA DER SignatureValue and RFC 8410 SPKI/PKCS8
formats. The general BER/DER reader, canonical validator, OID, and owned
value-tree implementation and conformance tests belong to the standalone
`Salts::ASN1` C11 archive (export candidate qigao/crypto branch
`export/standalone-asn1-owner`; later qigao/asn1 repository).

Crypto remains one static native archive, and imports one standalone
provider-neutral `Salts::ASN1` target. No local second parser, compatibility
wrappers, CMeta, Core or GmSSL sources are introduced.

The installed C11/C++17 Crypto consumers must find both the ASN1 package and
Crypto package; imported `Salts::Crypto` links ASN1 transitively. Backend
GmSSL objects remain private to the Crypto archive.
