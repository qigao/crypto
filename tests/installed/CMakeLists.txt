cmake_minimum_required(VERSION 3.21)
project(CryptoInstalledOneOwnerAcceptance LANGUAGES C CXX)
include(CTest)
find_package(Crypto 0.1 CONFIG REQUIRED)
if(NOT TARGET Crypto::Provider)
  message(FATAL_ERROR "No installed Crypto::Provider target")
endif()
get_target_property(_kind Crypto::Provider TYPE)
get_target_property(_imported Crypto::Provider IMPORTED)
if(NOT _kind STREQUAL "SHARED_LIBRARY" OR NOT _imported)
  message(FATAL_ERROR "Installed Crypto Provider must be SHARED/IMPORTED, never static")
endif()

add_executable(crypto_consumer_c11 consumer.c)
target_compile_features(crypto_consumer_c11 PRIVATE c_std_11)
target_link_libraries(crypto_consumer_c11 PRIVATE Crypto::Provider)
set_target_properties(crypto_consumer_c11 PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME crypto.sdk.c11_sm3 COMMAND crypto_consumer_c11)

add_executable(crypto_consumer_cpp17 consumer.cpp)
target_compile_features(crypto_consumer_cpp17 PRIVATE cxx_std_17)
target_link_libraries(crypto_consumer_cpp17 PRIVATE Crypto::Provider)
add_test(NAME crypto.sdk.cpp17_sm3 COMMAND crypto_consumer_cpp17)

# Load TWO different MODULE images which independently import the one
# Crypto::Provider DSO. No static GmSSL object is linked into either module.
foreach(_probe IN ITEMS a b)
  add_library(crypto_probe_${_probe} MODULE probe_plugin.c)
  target_compile_features(crypto_probe_${_probe} PRIVATE c_std_11)
  set_target_properties(crypto_probe_${_probe} PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(crypto_probe_${_probe} PRIVATE Crypto::Provider)
endforeach()

add_executable(crypto_owner_consumer owner_consumer.c)
target_compile_features(crypto_owner_consumer PRIVATE c_std_11)
set_target_properties(crypto_owner_consumer PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(crypto_owner_consumer PRIVATE
  Crypto::Provider "${CMAKE_DL_LIBS}")
target_compile_definitions(crypto_owner_consumer PRIVATE
  "CRYPTO_PROBE_A=\"$<TARGET_FILE:crypto_probe_a>\""
  "CRYPTO_PROBE_B=\"$<TARGET_FILE:crypto_probe_b>\"")
add_dependencies(crypto_owner_consumer crypto_probe_a crypto_probe_b)
add_test(NAME crypto.sdk.two_modules_one_owner COMMAND crypto_owner_consumer)
set_tests_properties(crypto.sdk.two_modules_one_owner PROPERTIES TIMEOUT 15)
