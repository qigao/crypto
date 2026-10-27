#ifndef CRYPTO_ASN1_H
#define CRYPTO_ASN1_H

#include <stddef.h>
#include <stdint.h>

/* ASN.1 is part of the one static Salts::Crypto archive, never a DSO. */
#define CRYPTO_ASN1_PUBLIC

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_ASN1_ABI_VERSION 1u
#define CRYPTO_ASN1_MAX_DEPTH 32u

typedef enum crypto_asn1_mode {
    CRYPTO_ASN1_BER = 1,
    CRYPTO_ASN1_DER = 2
} crypto_asn1_mode;

typedef enum crypto_asn1_status {
    CRYPTO_ASN1_OK = 0,
    CRYPTO_ASN1_DONE = 1,
    CRYPTO_ASN1_INVALID_ARGUMENT = 2,
    CRYPTO_ASN1_UNEXPECTED_END = 3,
    CRYPTO_ASN1_INVALID_TAG = 4,
    CRYPTO_ASN1_INVALID_LENGTH = 5,
    CRYPTO_ASN1_MALFORMED = 6,
    CRYPTO_ASN1_LIMIT_EXCEEDED = 7,
    CRYPTO_ASN1_UNSUPPORTED = 8,
    CRYPTO_ASN1_TRAILING_DATA = 9,
    CRYPTO_ASN1_BUFFER_TOO_SMALL = 10,
    CRYPTO_ASN1_OUT_OF_MEMORY = 11
} crypto_asn1_status;

/* Borrowed view into caller-owned bytes. The source buffer must remain alive
 * and unchanged while the view or a child reader is in use. */
typedef struct crypto_asn1_tlv {
    uint8_t tag_class;
    uint8_t constructed;
    uint8_t indefinite_length;
    uint8_t reserved;
    uint32_t tag_number;
    const uint8_t *content;
    size_t content_size;     /* Excludes EOC for indefinite-length values. */
    size_t encoded_size;     /* Includes tag, length, content and EOC. */
    size_t depth;            /* Parser-validated nesting depth; do not modify. */
} crypto_asn1_tlv;

/* Stack-allocated reader facade. Treat fields as private after initialization. */
typedef struct crypto_asn1_reader {
    const uint8_t *data;
    size_t size;
    size_t offset;
    crypto_asn1_mode mode;
    size_t depth;
} crypto_asn1_reader;

CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_reader_init(
    crypto_asn1_reader *reader, const void *data, size_t size,
    crypto_asn1_mode mode);

/* Reads one complete TLV. DONE means input exhaustion. On parse failure, the
 * reader offset and output TLV remain unchanged. Constructed contents are
 * recursively validated before a TLV is returned. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_reader_next(
    crypto_asn1_reader *reader, crypto_asn1_tlv *out);

/* Opens validated children of a constructed TLV. The child reader borrows the
 * same buffer; indefinite-length EOC bytes are not exposed. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_reader_open_children(
    const crypto_asn1_reader *parent, const crypto_asn1_tlv *value,
    crypto_asn1_reader *children);

/* Validates exactly one complete encoded value and rejects trailing bytes.
 * DER mode rejects indefinite lengths and non-canonical universal encodings. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_validate(
    const void *data, size_t size, crypto_asn1_mode mode);

/* Encodes one canonical TLV into caller-owned storage. Constructed content must
 * itself be a valid sequence of complete TLVs. Indefinite length is BER-only
 * and only valid for constructed values. No output bytes are written on error.
 *
 * With output=NULL and output_capacity=0, performs a size query and returns
 * the required byte count in written. If the buffer is too small, returns
 * BUFFER_TOO_SMALL and reports the required size without modifying the buffer. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_encode_tlv(
    uint8_t tag_class, uint8_t constructed, uint32_t tag_number,
    const void *content, size_t content_size, crypto_asn1_mode mode,
    uint8_t indefinite_length, void *output, size_t output_capacity,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ASN1_H */
