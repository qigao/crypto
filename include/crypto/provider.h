#ifndef CRYPTO_PROVIDER_H
#define CRYPTO_PROVIDER_H

/* Pre-stable C11 ABI 0.1. GmSSL internals never cross this boundary. */
#include <stddef.h>
#include <stdint.h>
#define CRYPTO_PROVIDER_API
#ifdef __cplusplus
extern "C" {
#endif
#define CRYPTO_PROVIDER_ABI_VERSION UINT32_C(0x00000100)
#define CRYPTO_PROVIDER_SM3_SIZE 32u
typedef enum crypto_provider_result {
  CRYPTO_PROVIDER_OK = 0,
  CRYPTO_PROVIDER_INVALID_ARGUMENT = 1,
  CRYPTO_PROVIDER_UNSUPPORTED = 2,
  CRYPTO_PROVIDER_INTERNAL_ERROR = 3
} crypto_provider_result;

CRYPTO_PROVIDER_API void crypto_provider_abi_0_1_required(void);
CRYPTO_PROVIDER_API uint32_t crypto_provider_runtime_abi(void);
/* One-shot SM3 digest; only borrowed input and caller-owned fixed output.
 * NULL input is admitted only when data_size == 0, and a failed call must
 * leave the caller's output unchanged.
 */
CRYPTO_PROVIDER_API crypto_provider_result crypto_provider_sm3(
  const uint8_t *data, size_t data_size, uint8_t *output, size_t output_size);

#ifdef __cplusplus
}
#endif
#endif /* CRYPTO_PROVIDER_H */
