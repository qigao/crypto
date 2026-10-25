#include <crypto/provider.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <type_traits>

static_assert(sizeof(crypto_provider_result) == sizeof(int),
              "C11 ABI result enumeration must match C++17 consumer");
int main() {
  crypto_provider_abi_0_1_required();
  std::array<std::uint8_t, CRYPTO_PROVIDER_SM3_SIZE> out{};
  static constexpr std::uint8_t expected[] = {
    0x66,0xc7,0xf0,0xf4,0x62,0xee,0xdd,0x9d,
    0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
    0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,
    0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
  };
  if (crypto_provider_runtime_abi() != CRYPTO_PROVIDER_ABI_VERSION)
    return 1;
  if (crypto_provider_sm3(
        reinterpret_cast<const uint8_t*>("abc"), 3,
        out.data(), out.size()) != CRYPTO_PROVIDER_OK)
    return 2;
  if (std::memcmp(out.data(), expected, out.size())) {
    std::fprintf(stderr, "C++17 SM3(abc) observed=");
    for(auto byte:out) std::fprintf(stderr, "%02x", byte);
    std::fprintf(stderr, "\\n");
    return 3;
  }
  return 0;
}
