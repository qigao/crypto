cmake_minimum_required(VERSION 3.21)
# Test-only qualification: compile the exact Crypto-owned ASN.1 source files
# into isolated executables without a GmSSL installation or a second SDK
# archive/DSO. Nothing here is exported or installed.
project(CryptoASN1SourceConformance LANGUAGES C CXX)
include(CTest)
get_filename_component(_crypto_source_root
  "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(_asn1_implementation
  "${_crypto_source_root}/src/asn1/reader.c"
  "${_crypto_source_root}/src/asn1/value.c"
  "${_crypto_source_root}/src/asn1/crypto.c")
foreach(_name IN ITEMS reader value crypto)
  add_executable(asn1_source_${_name}
    "${CMAKE_CURRENT_LIST_DIR}/../${_name}.c"
    ${_asn1_implementation})
  set_target_properties(asn1_source_${_name} PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(asn1_source_${_name}
    PRIVATE "${_crypto_source_root}/include")
  add_test(NAME asn1.source.${_name} COMMAND asn1_source_${_name})
endforeach()
add_executable(asn1_source_cpp
  "${CMAKE_CURRENT_LIST_DIR}/../header_cpp.cpp"
  ${_asn1_implementation})
set_target_properties(asn1_source_cpp PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_include_directories(asn1_source_cpp PRIVATE
  "${_crypto_source_root}/include")
add_test(NAME asn1.source.cpp17 COMMAND asn1_source_cpp)
