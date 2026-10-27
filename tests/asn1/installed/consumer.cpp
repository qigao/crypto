#include <crypto/asn1_value.h>
#include <crypto/asn1_crypto.h>

#include <cstdint>
#include <cstdio>

int main() {
    static_assert(CRYPTO_ASN1_RFC8410_KEY_BYTES == 32u, "RFC 8410 key ABI");
    crypto_asn1_value *sequence = nullptr;
    crypto_asn1_value *integer = nullptr;
    crypto_asn1_value *decoded = nullptr;
    std::uint8_t encoded[32]{};
    std::size_t written = 0u;
    std::int64_t number = 0;
    int result = 1;

    {
        auto status = crypto_asn1_value_create_sequence(&sequence);
        if (status != CRYPTO_ASN1_OK) { std::fprintf(stderr, "create_sequence=%d\n", (int)status); goto done; }
        status = crypto_asn1_value_create_integer(128, &integer);
        if (status != CRYPTO_ASN1_OK) { std::fprintf(stderr, "create_integer=%d\n", (int)status); goto done; }
        status = crypto_asn1_value_add_child(sequence, integer);
        if (status != CRYPTO_ASN1_OK) { std::fprintf(stderr, "add_child=%d\n", (int)status); goto done; }
        integer = nullptr; /* ownership transferred to sequence */
        status = crypto_asn1_value_encode(sequence, CRYPTO_ASN1_DER, 0u,
                                          encoded, sizeof(encoded), &written);
        if (status != CRYPTO_ASN1_OK) { std::fprintf(stderr, "value_encode=%d\n", (int)status); goto done; }
        status = crypto_asn1_value_decode(encoded, written, CRYPTO_ASN1_DER, &decoded);
        if (status != CRYPTO_ASN1_OK) { std::fprintf(stderr, "value_decode=%d\n", (int)status); goto done; }
        if (crypto_asn1_value_child_count(decoded) != 1u) {
            std::fprintf(stderr, "child_count=%zu\n", crypto_asn1_value_child_count(decoded)); goto done;
        }
        status = crypto_asn1_value_get_integer_i64(
            crypto_asn1_value_child_at(decoded, 0u), &number);
        if (status != CRYPTO_ASN1_OK || number != 128) {
            std::fprintf(stderr, "get_integer=%d number=%lld\n", (int)status, (long long)number); goto done;
        }
    }
    result = 0;

done:
    crypto_asn1_value_free(decoded);
    crypto_asn1_value_free(sequence);
    crypto_asn1_value_free(integer);
    return result;
}
