cmake_minimum_required(VERSION 3.21)
project(CryptoUnifiedInstalledOwner LANGUAGES C CXX)
include(CTest)

# Both public packages must import exactly ONE native TLS/GmSSL image.
find_package(Crypto 0.1 CONFIG REQUIRED)
find_package(CryptoTLS 0.1 CONFIG REQUIRED)
foreach(_forbidden_ns IN ITEMS Crypto SaltsCrypto)
  foreach(_target IN ITEMS TLS Provider TLSHost TLSCipherBIO CryptoProvider)
    if(TARGET "${_forbidden_ns}::${_target}")
      message(FATAL_ERROR "Noncanonical ${_forbidden_ns}::${_target} target exported")
    endif()
  endforeach()
endforeach()
if(NOT TARGET Salts::CryptoProvider OR NOT TARGET Salts::TLS)
  message(FATAL_ERROR "Both imported Crypto API views are mandatory")
endif()
get_target_property(_provider_kind Salts::CryptoProvider TYPE)
get_target_property(_tls_kind Salts::TLS TYPE)
get_target_property(_provider_imported Salts::CryptoProvider IMPORTED)
get_target_property(_tls_imported Salts::TLS IMPORTED)
get_target_property(_provider_links Salts::CryptoProvider INTERFACE_LINK_LIBRARIES)
if(NOT _provider_kind STREQUAL "INTERFACE_LIBRARY"
   OR NOT _tls_kind STREQUAL "SHARED_LIBRARY"
   OR NOT _provider_imported OR NOT _tls_imported
   OR NOT "Salts::TLS" IN_LIST _provider_links)
  message(FATAL_ERROR "Duplicate GmSSL owner or unexpected ABI package target")
endif()
unset(_provider_links)
unset(_tls_kind)
unset(_provider_kind)
unset(_provider_imported)
unset(_tls_imported)

add_executable(crypto_owner_c11 consumer.c)
set_target_properties(crypto_owner_c11 PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(crypto_owner_c11 PRIVATE Salts::CryptoProvider Salts::TLS)
add_test(NAME crypto.unified.c11_sm3_and_tls COMMAND crypto_owner_c11)

add_executable(crypto_owner_cpp17 consumer.cpp)
set_target_properties(crypto_owner_cpp17 PROPERTIES
  CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
target_link_libraries(crypto_owner_cpp17 PRIVATE Salts::CryptoProvider Salts::TLS)
add_test(NAME crypto.unified.cpp17_sm3_and_tls COMMAND crypto_owner_cpp17)

# These are TWO independent C11 MODULE images, both dynamically importing
# exactly the same single GmSSL-bearing Crypto TLS DSO (no backend archives).
foreach(_name IN ITEMS a b)
  add_library(crypto_owner_plugin_${_name} MODULE probe_plugin.c)
  set_target_properties(crypto_owner_plugin_${_name} PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(crypto_owner_plugin_${_name}
    PRIVATE Salts::CryptoProvider Salts::TLS)
endforeach()

add_executable(crypto_owner_process owner_consumer.c)
set_target_properties(crypto_owner_process PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(crypto_owner_process PRIVATE
  Salts::CryptoProvider Salts::TLS "${CMAKE_DL_LIBS}")
target_compile_definitions(crypto_owner_process PRIVATE
  "CRYPTO_PROBE_A=\"$<TARGET_FILE:crypto_owner_plugin_a>\""
  "CRYPTO_PROBE_B=\"$<TARGET_FILE:crypto_owner_plugin_b>\"")
add_dependencies(crypto_owner_process
  crypto_owner_plugin_a crypto_owner_plugin_b)
if(WIN32)
  # A real relocation consumer must load the same installed DLL, not obtain
  # a second source/archive copy. Copy only that single native DLL.
  add_custom_command(TARGET crypto_owner_process POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "$<TARGET_FILE:Salts::TLS>" "$<TARGET_FILE_DIR:crypto_owner_process>"
    VERBATIM)
  add_custom_command(TARGET crypto_owner_c11 POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "$<TARGET_FILE:Salts::TLS>" "$<TARGET_FILE_DIR:crypto_owner_c11>"
    VERBATIM)
  add_custom_command(TARGET crypto_owner_cpp17 POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "$<TARGET_FILE:Salts::TLS>" "$<TARGET_FILE_DIR:crypto_owner_cpp17>"
    VERBATIM)
endif()
add_test(NAME crypto.unified.two_modules_one_native_owner
  COMMAND crypto_owner_process)
set_tests_properties(crypto.unified.two_modules_one_native_owner
  PROPERTIES TIMEOUT 30)
