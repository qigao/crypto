cmake_minimum_required(VERSION 3.21)
project(SaltsCryptoModules VERSION 0.1.0 LANGUAGES C)
# qigao/crypto consists of exactly two independently buildable C11 modules.
# ASN1 has no dependency on Crypto or GmSSL. Crypto uses the same one ASN1.
include(CTest)
option(SALTS_CRYPTO_BUILD_CRYPTO "Build the GmSSL-backed Crypto module" ON)
add_subdirectory(asn1)
if(SALTS_CRYPTO_BUILD_CRYPTO)
  add_subdirectory(crypto)
endif()

if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME crypto.modules.source_owner
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_module_ownership.py")
endif()
