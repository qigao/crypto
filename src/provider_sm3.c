#define CRYPTO_PROVIDER_BUILDING 1
#include <crypto/provider.h>
/* Private backend header: no GmSSL structs in installed Crypto headers. */
#include <gmssl/sm3.h>
void crypto_provider_abi_0_1_required(void) {}
uint32_t crypto_provider_runtime_abi(void) {
  return CRYPTO_PROVIDER_ABI_VERSION;
}
crypto_provider_result crypto_provider_sm3(
    const uint8_t *data, size_t data_size, uint8_t *output, size_t output_size) {
  SM3_CTX ctx;
  if (output == NULL || output_size < CRYPTO_PROVIDER_SM3_SIZE ||
      (data == NULL && data_size != 0u)) {
    return CRYPTO_PROVIDER_INVALID_ARGUMENT;
  }
  sm3_init(&ctx);
  if (data_size != 0u) sm3_update(&ctx, data, data_size);
  sm3_finish(&ctx, output);
  {
    volatile uint8_t *p = (volatile uint8_t *)&ctx;
    size_t i;
    for (i = 0u; i < sizeof(ctx); ++i) p[i] = 0u;
  }
  return CRYPTO_PROVIDER_OK;
}
