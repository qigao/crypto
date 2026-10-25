cmake_minimum_required(VERSION 3.21)
project(CryptoTLS VERSION 0.1.0 LANGUAGES C)

# The GmSSL source is assembled in a separate, exact-SHA checkout by the
# provenance gate. This project does not fetch sources or export GmSSLConfig.
if(NOT DEFINED CRYPTO_GMSSL_SOURCE OR
   NOT EXISTS "${CRYPTO_GMSSL_SOURCE}/include/gmssl/tls.h")
  message(FATAL_ERROR "CRYPTO_GMSSL_SOURCE must be the verified patched checkout")
endif()
if(NOT DEFINED CRYPTO_GMSSL_STATIC OR
   NOT EXISTS "${CRYPTO_GMSSL_STATIC}")
  message(FATAL_ERROR "CRYPTO_GMSSL_STATIC must be its real compiled PIC static library")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
add_library(PrivateGmSSL STATIC IMPORTED)
set_target_properties(PrivateGmSSL PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_GMSSL_STATIC}"
  INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_GMSSL_SOURCE}/include")

add_library(CryptoTLSProvider SHARED src/crypto_tls_gmssl.c)
add_library(Crypto::TLS ALIAS CryptoTLSProvider)
set_target_properties(CryptoTLSProvider PROPERTIES
  OUTPUT_NAME crypto_tls
  EXPORT_NAME TLS
  C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
  C_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN YES
  POSITION_INDEPENDENT_CODE YES
  VERSION ${PROJECT_VERSION} SOVERSION 0)
target_include_directories(CryptoTLSProvider
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_definitions(CryptoTLSProvider PRIVATE
  CRYPTO_TLS_BUILD_DLL=1
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1
  ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)
target_link_libraries(CryptoTLSProvider PRIVATE PrivateGmSSL)

if(WIN32)
  # Only explicitly marked CRYPTO_TLS_API functions may be exported. The
  # imported GmSSL static archive must not become a second public ABI.
  set_target_properties(CryptoTLSProvider PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS OFF)
  target_link_libraries(CryptoTLSProvider PRIVATE Ws2_32)
elseif(APPLE)
  target_link_libraries(CryptoTLSProvider PRIVATE "-framework Security")
  target_link_options(CryptoTLSProvider PRIVATE
    "LINKER:-exported_symbols_list,${PROJECT_SOURCE_DIR}/cmake/crypto_tls.macos.exports")
elseif(UNIX)
  target_link_libraries(CryptoTLSProvider PRIVATE m "${CMAKE_DL_LIBS}")
  target_link_options(CryptoTLSProvider PRIVATE
    "LINKER:--version-script=${PROJECT_SOURCE_DIR}/cmake/crypto_tls.elf.map"
    "LINKER:--exclude-libs,ALL")
endif()

install(TARGETS CryptoTLSProvider
  EXPORT CryptoTLSTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/crypto/tls.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/crypto)
install(EXPORT CryptoTLSTargets
  NAMESPACE Crypto:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CryptoTLS)
configure_package_config_file(
  cmake/CryptoTLSConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoTLSConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CryptoTLS)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoTLSConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoTLSConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoTLSConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CryptoTLS)
