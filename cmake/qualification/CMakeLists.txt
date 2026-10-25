cmake_minimum_required(VERSION 3.21)
project(CryptoGmSSLAssembledSourceContract LANGUAGES C)
include(CTest)
find_package(Threads REQUIRED)

if(NOT DEFINED GMSSL_ASSEMBLED_SOURCE OR
   NOT EXISTS "${GMSSL_ASSEMBLED_SOURCE}/include/gmssl/tls.h")
  message(FATAL_ERROR "Need the exact assembled GmSSL checkout")
endif()
if(NOT DEFINED GMSSL_ASSEMBLED_LIBRARY OR
   NOT EXISTS "${GMSSL_ASSEMBLED_LIBRARY}")
  message(FATAL_ERROR "Need compiled private GmSSL 3.2 static provider")
endif()
# Test-local binary import. This is NOT a public GmSSLConfig package and
# cannot be shipped by Crypto. One provider owner must be qualified later.
add_library(GmSSLPrivateQualification STATIC IMPORTED)
set_target_properties(GmSSLPrivateQualification PROPERTIES
  IMPORTED_LOCATION "${GMSSL_ASSEMBLED_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${GMSSL_ASSEMBLED_SOURCE}/include"
  INTERFACE_COMPILE_DEFINITIONS
    "ENABLE_TLS;ENABLE_SECP256R1;ENABLE_SECP384R1;ENABLE_SHA1;ENABLE_SHA2;ENABLE_AES")
set(_gmssl_tests "${CMAKE_CURRENT_LIST_DIR}/../../providers/gmssl/tests")

function(crypto_gmssl_original_case case_name file_name)
  add_executable("crypto_original_${case_name}" "${_gmssl_tests}/${file_name}")
  set_target_properties("crypto_original_${case_name}" PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries("crypto_original_${case_name}" PRIVATE
    GmSSLPrivateQualification Threads::Threads "${CMAKE_DL_LIBS}")
  if(UNIX)
    target_link_libraries("crypto_original_${case_name}" PRIVATE m)
  endif()
  add_test(NAME "gmssl.original.${case_name}"
    COMMAND "crypto_original_${case_name}")
  set_tests_properties("gmssl.original.${case_name}" PROPERTIES TIMEOUT 60)
endfunction()

crypto_gmssl_original_case(tls_abi_layout tls-abi-layout-contract.c)
crypto_gmssl_original_case(p256_ecdsa_der p256-ecdsa-der-contract.c)
crypto_gmssl_original_case(rsa_public rsa-public-contract.c)
crypto_gmssl_original_case(tls_cleanup tls-cleanup-contract.c)
crypto_gmssl_original_case(x509_p384_sha384 x509-p384-sha384-contract.c)

foreach(_fixture IN ITEMS p384-ca p384-leaf p256-ca p256-leaf)
  string(TOUPPER "${_fixture}" _label)
  string(REPLACE "-" "_" _label "${_label}")
  set(_path "${_gmssl_tests}/fixtures/${_fixture}-sha384.pem")
  target_compile_definitions(crypto_original_x509_p384_sha384 PRIVATE
    "GMSSL_${_label}=\"${_path}\"")
endforeach()
