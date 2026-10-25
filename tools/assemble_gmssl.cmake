cmake_minimum_required(VERSION 3.21)

# Replays original port's 40 *source* adaptations against exact GmSSL
# checkout without owning portfile, manifest, packages or registry versions.
if(NOT DEFINED GMSSL_UPSTREAM_SOURCE OR NOT IS_DIRECTORY "${GMSSL_UPSTREAM_SOURCE}")
  message(FATAL_ERROR "GMSSL_UPSTREAM_SOURCE requires an upstream checkout")
endif()
get_filename_component(SOURCE_PATH "${GMSSL_UPSTREAM_SOURCE}" REALPATH)
get_filename_component(_crypto_root "${CMAKE_CURRENT_LIST_DIR}/.." REALPATH)
set(_patch_root "${_crypto_root}/providers/gmssl/patches")
set(_order_json "${_crypto_root}/providers/gmssl/provenance/patch-order.json")
if(NOT EXISTS "${_order_json}")
  message(FATAL_ERROR "Missing source-patch order attestation")
endif()

find_program(_git_executable NAMES git REQUIRED)
execute_process(
  COMMAND "${_git_executable}" -C "${SOURCE_PATH}" rev-parse HEAD
  OUTPUT_VARIABLE _sha OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE _code)
if(NOT _code EQUAL 0 OR NOT _sha STREQUAL
    "7c9f02904ef33e59c87b4f16621cc8fd434e7579")
  message(FATAL_ERROR "Incorrect upstream GmSSL 3.2.0 source: ${_sha}")
endif()
execute_process(
  COMMAND "${_git_executable}" -C "${SOURCE_PATH}" status --porcelain
  OUTPUT_VARIABLE _dirty OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE _code)
if(NOT _code EQUAL 0 OR NOT "${_dirty}" STREQUAL "")
  message(FATAL_ERROR "GmSSL upstream checkout must be clean")
endif()

file(READ "${_order_json}" _order)
string(JSON _first GET "${_order}" first_git_apply_patch)
string(JSON _n LENGTH "${_order}" ordered_cmake_source_adaptations)
if(NOT _first STREQUAL "providers/gmssl/patches/p256-ecdsa-der-signature-parsing.patch"
   OR NOT _n EQUAL 39)
  message(FATAL_ERROR "Unexpected 40-step original GmSSL source patch sequence")
endif()
set(_first_patch "${_crypto_root}/${_first}")
execute_process(
  COMMAND "${_git_executable}" -C "${SOURCE_PATH}" apply --check "${_first_patch}"
  RESULT_VARIABLE _check ERROR_VARIABLE _git_error)
if(NOT _check EQUAL 0)
  message(FATAL_ERROR "First GmSSL DER patch failed preflight: ${_git_error}")
endif()
execute_process(
  COMMAND "${_git_executable}" -C "${SOURCE_PATH}" apply "${_first_patch}"
  RESULT_VARIABLE _check ERROR_VARIABLE _git_error)
if(NOT _check EQUAL 0)
  message(FATAL_ERROR "First GmSSL DER patch rejected: ${_git_error}")
endif()

# A narrow test/assembly shim implementing the same replacement semantics
# needed by frozen source scripts, with fail-closed anchor validation.
# This does NOT copy vcpkg's public package ownership/registry into Crypto.
function(vcpkg_replace_string file_path find_text replace_text)
  if(NOT EXISTS "${file_path}" OR "${find_text}" STREQUAL "")
    message(FATAL_ERROR "Bad GmSSL source replacement input: ${file_path}")
  endif()
  file(READ "${file_path}" _old)
  string(FIND "${_old}" "${find_text}" _offset)
  if(_offset EQUAL -1)
    message(FATAL_ERROR "Missing upstream adaptation anchor in ${file_path}")
  endif()
  string(REPLACE "${find_text}" "${replace_text}" _new "${_old}")
  if("${_new}" STREQUAL "${_old}")
    message(FATAL_ERROR "No-op GmSSL patch in ${file_path}")
  endif()
  file(WRITE "${file_path}" "${_new}")
endfunction()

# Preserve original vcpkg source effects: ignore upstream hardcoded Windows
# install directory and build GmSSL as a private static implementation.
vcpkg_replace_string(
  "${SOURCE_PATH}/CMakeLists.txt"
  "set(CMAKE_INSTALL_PREFIX \"C:/Program Files/GmSSL\")"
  "# Install prefix is selected by the Crypto qualification host")
vcpkg_replace_string(
  "${SOURCE_PATH}/CMakeLists.txt"
  "add_library(gmssl \${src})"
  "add_library(gmssl STATIC \${src})")

math(EXPR _last "${_n} - 1")
foreach(_i RANGE 0 ${_last})
  string(JSON _script GET "${_order}" ordered_cmake_source_adaptations ${_i})
  if(NOT _script MATCHES
      "^providers/gmssl/patches/[a-zA-Z0-9._-]+[.]cmake$")
    message(FATAL_ERROR "Unsafe or unknown source patch: ${_script}")
  endif()
  if(NOT EXISTS "${_crypto_root}/${_script}")
    message(FATAL_ERROR "Missing original source patch: ${_script}")
  endif()
  include("${_crypto_root}/${_script}")
  message(STATUS "GmSSL source patch ${_i}: ${_script}")
endforeach()

file(SHA256 "${SOURCE_PATH}/CMakeLists.txt" _cmake_sha)
file(SHA256 "${SOURCE_PATH}/include/gmssl/tls.h" _tls_header_sha)
file(SHA256 "${SOURCE_PATH}/src/tls.c" _tls_source_sha)
if(DEFINED GMSSL_ASSEMBLY_RECEIPT)
  get_filename_component(_receipt_dir "${GMSSL_ASSEMBLY_RECEIPT}" DIRECTORY)
  file(MAKE_DIRECTORY "${_receipt_dir}")
  file(WRITE "${GMSSL_ASSEMBLY_RECEIPT}"
    "{\n"
    "  \"classification\": \"PATCHED_GMSSL_SOURCE_NOT_CRYPTO_PROVIDER_RELEASE\",\n"
    "  \"upstream_commit\": \"${_sha}\",\n"
    "  \"original_port_version\": \"3.2.0#13\",\n"
    "  \"git_patch_count\": 1,\n"
    "  \"source_adaptations\": ${_n},\n"
    "  \"cmakelists_sha256\": \"${_cmake_sha}\",\n"
    "  \"tls_header_sha256\": \"${_tls_header_sha}\",\n"
    "  \"tls_source_sha256\": \"${_tls_source_sha}\"\n"
    "}\n")
endif()
message(STATUS "GmSSL source assembled: one git patch plus ${_n} CMake adaptations")
