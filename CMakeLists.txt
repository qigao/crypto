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

add_library(CryptoTLSProvider SHARED src/crypto_tls_gmssl.c src/provider_sm3.c)
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
  CRYPTO_PROVIDER_BUILDING=1
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1
  ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)
target_link_libraries(CryptoTLSProvider PRIVATE PrivateGmSSL)

# One physical shared image owns the private GmSSL archive. The SM3
# Crypto::Provider CMake view is an INTERFACE alias of Crypto::TLS, not a
# second SHARED/STATIC binary. Export both views from one target set.
add_library(CryptoProviderView INTERFACE)
add_library(Crypto::Provider ALIAS CryptoProviderView)
set_target_properties(CryptoProviderView PROPERTIES EXPORT_NAME Provider)
target_link_libraries(CryptoProviderView INTERFACE CryptoTLSProvider)

if(MSVC)
  # MSVC C11 stdatomic.h remains an explicit opt-in on VS 2026. Use
  # standard lock-free C atomics, not a C++ runtime or unsafe emulation.
  target_compile_options(CryptoTLSProvider PRIVATE /experimental:c11atomics)
endif()

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

# Host loader owns only explicit OS dynamic-library references and lease
# control blocks; it never links or embeds GmSSL nor the Crypto TLS DSO.
add_library(CryptoTLSHost STATIC src/crypto_tls_loader.c)
add_library(Crypto::TLSHost ALIAS CryptoTLSHost)
set_target_properties(CryptoTLSHost PROPERTIES
  OUTPUT_NAME crypto_tls_host EXPORT_NAME TLSHost
  C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
  POSITION_INDEPENDENT_CODE YES)
target_include_directories(CryptoTLSHost PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
if(MSVC)
  target_compile_options(CryptoTLSHost PRIVATE /experimental:c11atomics)
endif()
if(WIN32)
  target_link_libraries(CryptoTLSHost PUBLIC Kernel32)
elseif(UNIX)
  target_link_libraries(CryptoTLSHost PUBLIC "${CMAKE_DL_LIBS}")
endif()

install(TARGETS CryptoTLSProvider CryptoTLSHost CryptoProviderView
  EXPORT CryptoTLSTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/crypto/tls.h include/crypto/tls_ext.h include/crypto/tls_peer.h include/crypto/loader.h include/crypto/provider.h
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

# The Crypto package exposes a provider-neutral SM3 interface view over the
# exact same physical crypto_tls DLL/dylib/so imported by CryptoTLSConfig.
# Do not install a second GmSSL-bearing crypto_provider image.
configure_package_config_file(
  cmake/CryptoConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Crypto)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Crypto)
