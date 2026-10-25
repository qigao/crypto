cmake_minimum_required(VERSION 3.21)
project(Crypto VERSION 0.1.0 LANGUAGES C)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(NOT DEFINED CRYPTO_GMSSL_SOURCE OR
   NOT EXISTS "${CRYPTO_GMSSL_SOURCE}/include/gmssl/sm3.h")
  message(FATAL_ERROR "Crypto Provider requires exact assembled GmSSL source")
endif()
if(NOT DEFINED CRYPTO_GMSSL_LIBRARY OR
   NOT EXISTS "${CRYPTO_GMSSL_LIBRARY}")
  message(FATAL_ERROR "Crypto Provider requires exact private GmSSL static library")
endif()
if(BUILD_SHARED_LIBS)
  message(FATAL_ERROR "Only one explicit SHARED Crypto Provider owns GmSSL source")
endif()
add_library(crypto_gmssl_private STATIC IMPORTED)
set_target_properties(crypto_gmssl_private PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_GMSSL_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_GMSSL_SOURCE}/include")

add_library(crypto_provider SHARED src/provider_sm3.c)
add_library(Crypto::Provider ALIAS crypto_provider)
set_target_properties(crypto_provider PROPERTIES
  EXPORT_NAME Provider
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
  VERSION "${PROJECT_VERSION}" SOVERSION "0.1")
target_compile_definitions(crypto_provider PRIVATE CRYPTO_PROVIDER_BUILDING=1)
target_include_directories(crypto_provider PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(crypto_provider PRIVATE crypto_gmssl_private)

if(WIN32)
  set_target_properties(crypto_provider PROPERTIES OUTPUT_NAME "crypto_provider-0.1")
elseif(APPLE)
  target_link_options(crypto_provider PRIVATE
    "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/cmake/crypto-provider.exports")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_options(crypto_provider PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/crypto-provider.map"
    "-Wl,--exclude-libs,ALL")
else()
  message(FATAL_ERROR "No approved native exported-symbol policy for this OS")
endif()

install(TARGETS crypto_provider EXPORT CryptoTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES include/crypto/provider.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/crypto")
configure_package_config_file(cmake/CryptoConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Crypto")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}" COMPATIBILITY SameMinorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Crypto")
install(EXPORT CryptoTargets FILE CryptoTargets.cmake NAMESPACE Crypto::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Crypto")
message(STATUS "Crypto 0.1 shared SM3 provider only; TLS/X509 API pending")
