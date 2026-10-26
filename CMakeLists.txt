cmake_minimum_required(VERSION 3.21)
project(SaltsCrypto VERSION 0.1.0 LANGUAGES C)

# Exactly one installed STATIC archive and one CMake target: Salts::Crypto.
# GmSSL 3.2 is a pinned source/build input, never a separate SDK library.
foreach(_input IN ITEMS CRYPTO_GMSSL_SOURCE CRYPTO_GMSSL_STATIC)
  if(NOT DEFINED ${_input} OR NOT EXISTS "${${_input}}")
    message(FATAL_ERROR "${_input} must point at the verified patched GmSSL source/archive")
  endif()
endforeach()
if(NOT EXISTS "${CRYPTO_GMSSL_SOURCE}/include/gmssl/tls.h")
  message(FATAL_ERROR "GmSSL TLS headers missing from verified source")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Ed448 libecc source uses the reviewed 64-bit WORDSIZE ABI")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)
find_package(Threads REQUIRED)

set(_libecc "${CMAKE_CURRENT_SOURCE_DIR}/vendor/libecc")
# Compile libecc's reviewed Ed448 subset in its own internal OBJECT target.
# Fold these objects directly into the sole installed Salts::Crypto archive.
add_subdirectory(vendor/libecc)

# No separate libecc archive; only its required Ed448 code is compiled.
# SHA256 is the existing, pinned GmSSL implementation, not a duplicate libecc SHA.
add_library(salts_crypto STATIC
  src/provider_sm3.c
  src/crypto_tls_gmssl.c
  src/crypto_tls_cipher_bio.c
  src/crypto_ed448.c
  src/crypto_sha256.c
  src/crypto_random.c
  $<TARGET_OBJECTS:crypto_libecc_ed448_objects>)
add_library(Salts::Crypto ALIAS salts_crypto)
set_target_properties(salts_crypto PROPERTIES
  OUTPUT_NAME salts_crypto EXPORT_NAME Crypto
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_compile_features(salts_crypto PUBLIC c_std_11)
target_link_libraries(salts_crypto PUBLIC Threads::Threads)
target_include_directories(salts_crypto
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE "${CRYPTO_GMSSL_SOURCE}/include"
          "${_libecc}/include")
target_compile_definitions(salts_crypto PRIVATE
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1
  ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)

# Keep the Ed448 facade's configuration consistent with the private object
# target. No SHA256/SM3 libecc implementation or alternate RNG is built.
set_source_files_properties(src/crypto_ed448.c
  PROPERTIES COMPILE_DEFINITIONS
  "WITH_STDLIB;WITH_LIBECC_CONFIG_OVERRIDE;WITH_CURVE_WEI448;WITH_HASH_SHAKE256;WITH_SIG_EDDSA448;WORDSIZE=64")

if(MSVC)
  target_compile_options(salts_crypto PRIVATE /experimental:c11atomics)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32)
elseif(WIN32)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32)
elseif(APPLE)
  target_link_libraries(salts_crypto PUBLIC "-framework Security")
elseif(UNIX)
  target_link_libraries(salts_crypto PUBLIC m "${CMAKE_DL_LIBS}")
endif()

# Fold ALL compiled native GmSSL objects into this one installed archive.
# PrivateGmSSL is neither an installed/imported target nor a consumer dependency.
add_custom_command(TARGET salts_crypto POST_BUILD
  COMMAND "${CMAKE_COMMAND}"
    "-DARCHIVE=$<TARGET_FILE:salts_crypto>"
    "-DGMSSL_ARCHIVE=${CRYPTO_GMSSL_STATIC}"
    "-DARCHIVER=${CMAKE_AR}"
    "-DRANLIB=${CMAKE_RANLIB}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/merge_static_crypto.cmake"
  VERBATIM)

install(TARGETS salts_crypto EXPORT SaltsCryptoTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/crypto include/salts
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h")
install(FILES "${_libecc}/LICENSE"
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Crypto/libecc)

set(_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/Crypto")
install(EXPORT SaltsCryptoTargets FILE CryptoTargets.cmake
  NAMESPACE Salts:: DESTINATION "${_package_dir}")
configure_package_config_file(cmake/CryptoConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  INSTALL_DESTINATION "${_package_dir}")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  DESTINATION "${_package_dir}")

if(BUILD_TESTING)
  enable_language(CXX)
  add_subdirectory(tests/algorithms)
endif()
