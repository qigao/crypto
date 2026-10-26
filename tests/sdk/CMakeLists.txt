cmake_minimum_required(VERSION 3.21)
project(CryptoInstalledC11Consumer LANGUAGES C)
include(CTest)
find_package(CryptoTLS CONFIG REQUIRED)

# This project is configured independently against the *installed* prefix.
# Its ONLY public dependency is Crypto::TLS and <crypto/tls.h>.
if(NOT DEFINED CRYPTO_TEST_FIXTURES)
  message(FATAL_ERROR "CRYPTO_TEST_FIXTURES must point to original cert fixtures")
endif()
foreach(_cert IN ITEMS
    external-io-ca-cert.pem
    external-io-server-cert.pem
    external-io-server-key.pem)
  if(NOT EXISTS "${CRYPTO_TEST_FIXTURES}/${_cert}")
    message(FATAL_ERROR "Missing original external IO fixture ${_cert}")
  endif()
endforeach()
file(TO_CMAKE_PATH "${CRYPTO_TEST_FIXTURES}/external-io-ca-cert.pem" _ca)
file(TO_CMAKE_PATH "${CRYPTO_TEST_FIXTURES}/external-io-server-cert.pem" _cert)
file(TO_CMAKE_PATH "${CRYPTO_TEST_FIXTURES}/external-io-server-key.pem" _key)

add_executable(crypto_sdk_consumer consumer.c)
set_target_properties(crypto_sdk_consumer PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(crypto_sdk_consumer PRIVATE Crypto::TLS)
target_compile_definitions(crypto_sdk_consumer PRIVATE
  "SDK_CA_FILE=\"${_ca}\""
  "SDK_SERVER_CERT_FILE=\"${_cert}\""
  "SDK_SERVER_KEY_FILE=\"${_key}\"")
add_executable(crypto_sdk_dso dso.c)
# The DSO host is NOT linked to Crypto: use only the installed public
# header path advertised by the imported package.
target_include_directories(crypto_sdk_dso PRIVATE
  "$<TARGET_PROPERTY:Crypto::TLS,INTERFACE_INCLUDE_DIRECTORIES>")
set_target_properties(crypto_sdk_dso PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(UNIX AND NOT APPLE)
  target_link_libraries(crypto_sdk_dso PRIVATE "${CMAKE_DL_LIBS}")
elseif(APPLE)
  target_link_libraries(crypto_sdk_dso PRIVATE "${CMAKE_DL_LIBS}")
endif()
# Windows requires the installed Crypto DLL beside the exe at runtime. The
# same copy is harmless on macOS/Linux; provider source is still one DSO.
add_custom_command(TARGET crypto_sdk_consumer POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "$<TARGET_FILE:Crypto::TLS>" "$<TARGET_FILE_DIR:crypto_sdk_consumer>"
  VERBATIM)
add_test(NAME crypto.installed.real_tls12_tls13
  COMMAND crypto_sdk_consumer)
add_test(NAME crypto.installed.dso_unload
  COMMAND crypto_sdk_dso "$<TARGET_FILE:Crypto::TLS>")
set_tests_properties(crypto.installed.real_tls12_tls13
  crypto.installed.dso_unload PROPERTIES TIMEOUT 90)

option(CRYPTO_SDK_ENABLE_CONCURRENT_LIFECYCLE
  "Build real borrowed-callback race test (Unix native only)" OFF)
if(CRYPTO_SDK_ENABLE_CONCURRENT_LIFECYCLE)
  if(NOT UNIX)
    message(FATAL_ERROR "Concurrent pthread lifecycle gate needs a Unix native target")
  endif()
  find_package(Threads REQUIRED)
  add_executable(crypto_sdk_concurrency concurrency.c)
  set_target_properties(crypto_sdk_concurrency PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(crypto_sdk_concurrency
    PRIVATE Crypto::TLS Threads::Threads)
  target_compile_definitions(crypto_sdk_concurrency PRIVATE
    "SDK_CA_FILE=\"${_ca}\"")
  add_test(NAME crypto.installed.inflight_cancel_busy_destroy
    COMMAND crypto_sdk_concurrency)
  set_tests_properties(crypto.installed.inflight_cancel_busy_destroy
    PROPERTIES TIMEOUT 60)
endif()

option(CRYPTO_SDK_ENABLE_OPENSSL_PEER
  "Compile installed C11 facade TCP client for external OpenSSL 3 peers" OFF)
if(CRYPTO_SDK_ENABLE_OPENSSL_PEER)
  if(NOT UNIX)
    message(FATAL_ERROR "The independent OpenSSL socket-client gate is POSIX only")
  endif()
  add_executable(crypto_sdk_openssl_client openssl-client.c)
  set_target_properties(crypto_sdk_openssl_client PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(crypto_sdk_openssl_client PRIVATE Crypto::TLS)
  # Test-only REAL Crypto TLS socket server. OpenSSL3 s_client will obtain
  # its own exporter bytes from the SAME connection for an independent oracle.
  add_executable(crypto_sdk_openssl_server openssl-server.c)
  set_target_properties(crypto_sdk_openssl_server PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(crypto_sdk_openssl_server PRIVATE Crypto::TLS)
endif()

# Host-side lease tests intentionally link ONLY the installed static
# Crypto::TLSHost helper. They do not link the native Crypto TLS DSO or GmSSL.
option(CRYPTO_SDK_ENABLE_HOST_LEASE
  "Qualify C11 host-side dynamic loader admission and unload pinning" OFF)
option(CRYPTO_SDK_ENABLE_HOST_LEASE_RACE
  "Qualify true pthread TLS callback vs DSO unload under TSan" OFF)
if(CRYPTO_SDK_ENABLE_HOST_LEASE)
  if(NOT TARGET Crypto::TLSHost)
    message(FATAL_ERROR "Installed Crypto::TLSHost target required")
  endif()
  add_executable(crypto_sdk_host_loader loader.c)
  set_target_properties(crypto_sdk_host_loader PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(crypto_sdk_host_loader PRIVATE Crypto::TLSHost)
  # Test-only separate images: an incomplete symbol table and a full symbol
  # table with the wrong runtime ABI. Neither may be admitted by TLSHost.
  add_library(crypto_sdk_fake_partial SHARED fake-provider.c)
  add_library(crypto_sdk_fake_wrong_abi SHARED fake-provider.c)
  target_include_directories(crypto_sdk_fake_partial PRIVATE
    "$<TARGET_PROPERTY:Crypto::TLSHost,INTERFACE_INCLUDE_DIRECTORIES>")
  target_include_directories(crypto_sdk_fake_wrong_abi PRIVATE
    "$<TARGET_PROPERTY:Crypto::TLSHost,INTERFACE_INCLUDE_DIRECTORIES>")
  target_compile_definitions(crypto_sdk_fake_wrong_abi
    PRIVATE FAKE_FULL_WRONG_ABI=1)
  set_target_properties(crypto_sdk_fake_partial
    crypto_sdk_fake_wrong_abi PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  add_test(NAME crypto.installed.host_lease_unload
    COMMAND crypto_sdk_host_loader "$<TARGET_FILE:Crypto::TLS>"
      "$<TARGET_FILE:crypto_sdk_fake_partial>"
      "$<TARGET_FILE:crypto_sdk_fake_wrong_abi>")
  set_tests_properties(crypto.installed.host_lease_unload PROPERTIES TIMEOUT 120)
  if(CRYPTO_SDK_ENABLE_HOST_LEASE_RACE)
    if(NOT UNIX)
      message(FATAL_ERROR "Host DSO callback-race tests require native pthreads")
    endif()
    find_package(Threads REQUIRED)
    add_executable(crypto_sdk_host_loader_race loader_race.c)
    set_target_properties(crypto_sdk_host_loader_race PROPERTIES
      C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_link_libraries(crypto_sdk_host_loader_race
      PRIVATE Crypto::TLSHost Threads::Threads)
    target_compile_definitions(crypto_sdk_host_loader_race PRIVATE
      "SDK_CA_FILE=\"${_ca}\"")
    add_test(NAME crypto.installed.host_lease_callback_race
      COMMAND crypto_sdk_host_loader_race "$<TARGET_FILE:Crypto::TLS>")
    set_tests_properties(crypto.installed.host_lease_callback_race
      PROPERTIES TIMEOUT 120)
  endif()
elseif(CRYPTO_SDK_ENABLE_HOST_LEASE_RACE)
  message(FATAL_ERROR "Host DSO lease race requires CRYPTO_SDK_ENABLE_HOST_LEASE")
endif()
