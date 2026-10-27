#ifndef CRYPTO_ASN1_VALUE_H
#define CRYPTO_ASN1_VALUE_H

#include <crypto/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_asn1_value crypto_asn1_value;

/* Creates an owned value. Primitive content is copied; constructed values
 * must start empty and acquire children through add_child. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create(
    uint8_t tag_class, uint8_t constructed, uint32_t tag_number,
    const void *content, size_t content_size, crypto_asn1_value **out);

CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_sequence(
    crypto_asn1_value **out);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_set(
    crypto_asn1_value **out);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_boolean(
    int value, crypto_asn1_value **out);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_integer(
    int64_t value, crypto_asn1_value **out);
/* Creates a non-negative DER INTEGER from an unsigned big-endian magnitude.
 * Leading zero bytes are ignored. A zero-length/all-zero magnitude encodes as
 * INTEGER 0. The input is copied and may be released after return. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_unsigned_integer(
    const void *magnitude, size_t magnitude_size, crypto_asn1_value **out);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_bit_string(
    const void *data, size_t size, uint8_t unused_bits,
    crypto_asn1_value **out);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_octet_string(
    const void *data, size_t size, crypto_asn1_value **out);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_null(
    crypto_asn1_value **out);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_create_oid(
    const uint32_t *components, size_t count, crypto_asn1_value **out);

/* Ownership transfers only when add_child returns OK. A child can have one
 * parent only. Freeing a parent recursively frees all children. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_add_child(
    crypto_asn1_value *parent, crypto_asn1_value *child);
CRYPTO_ASN1_PUBLIC void crypto_asn1_value_free(crypto_asn1_value *value);

CRYPTO_ASN1_PUBLIC size_t crypto_asn1_value_child_count(
    const crypto_asn1_value *value);
CRYPTO_ASN1_PUBLIC const crypto_asn1_value *crypto_asn1_value_child_at(
    const crypto_asn1_value *value, size_t index);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_get_tag(
    const crypto_asn1_value *value, uint8_t *tag_class,
    uint8_t *constructed, uint32_t *tag_number);
/* Returns a borrowed view into value-owned primitive bytes. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_get_content(
    const crypto_asn1_value *value, const uint8_t **data, size_t *size);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_get_integer_i64(
    const crypto_asn1_value *value, int64_t *out);
/* Returns a borrowed minimal unsigned magnitude. INTEGER 0 is returned as one
 * zero byte. Negative INTEGER values are rejected as MALFORMED. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_get_unsigned_integer(
    const crypto_asn1_value *value, const uint8_t **magnitude,
    size_t *magnitude_size);
/* Returns a borrowed view excluding the initial unused-bits octet. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_get_bit_string(
    const crypto_asn1_value *value, const uint8_t **data, size_t *size,
    uint8_t *unused_bits);
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_get_boolean(
    const crypto_asn1_value *value, int *out);
/* If components is NULL, capacity must be zero; required_count is always set
 * on success or BUFFER_TOO_SMALL. OID arcs are limited to uint32_t. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_get_oid(
    const crypto_asn1_value *value, uint32_t *components, size_t capacity,
    size_t *required_count);

/* Decodes exactly one complete BER/DER value into an owned tree. Primitive
 * payloads are preserved byte-for-byte; typed accessors interpret common
 * universal types. The input buffer can be released after successful decode. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_decode(
    const void *data, size_t size, crypto_asn1_mode mode,
    crypto_asn1_value **out);

/* Encodes into caller-owned storage. If output is NULL and capacity is zero,
 * performs a validated size query. On error, caller output is not modified.
 * use_indefinite applies to all constructed nodes and is BER-only. */
CRYPTO_ASN1_PUBLIC crypto_asn1_status crypto_asn1_value_encode(
    const crypto_asn1_value *value, crypto_asn1_mode mode,
    uint8_t use_indefinite, void *output, size_t output_capacity,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ASN1_VALUE_H */
