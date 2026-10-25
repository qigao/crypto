cmake_minimum_required(VERSION 3.21)

# Source-level sanitizer fixes for the *Crypto candidate only*.
# Historical vcpkg-cache gmssl 3.2.0#13 and imported 92 provenance blobs
# remain immutable. Invoke AFTER the original 40 transformations.
if(NOT DEFINED GMSSL_ASSEMBLED_SOURCE OR
   NOT EXISTS "${GMSSL_ASSEMBLED_SOURCE}/src/tls12.c")
  message(FATAL_ERROR "Need a completely assembled pinned GmSSL source tree")
endif()
get_filename_component(_gmssl "${GMSSL_ASSEMBLED_SOURCE}" REALPATH)

function(crypto_replace_exactly_once path needle replacement)
  if(NOT EXISTS "${path}" OR "${needle}" STREQUAL "")
    message(FATAL_ERROR "Missing GmSSL source or invalid UB patch anchor: ${path}")
  endif()
  file(READ "${path}" _source)
  string(FIND "${_source}" "${needle}" _offset)
  if(_offset EQUAL -1)
    message(FATAL_ERROR "GmSSL source UB anchor not found in ${path}")
  endif()
  string(LENGTH "${needle}" _anchor_bytes)
  math(EXPR _after "${_offset} + ${_anchor_bytes}")
  string(SUBSTRING "${_source}" ${_after} -1 _suffix)
  string(FIND "${_suffix}" "${needle}" _another)
  if(NOT _another EQUAL -1)
    message(FATAL_ERROR "Ambiguous repeated GmSSL source UB anchor in ${path}")
  endif()
  string(REPLACE "${needle}" "${replacement}" _patched "${_source}")
  if("${_patched}" STREQUAL "${_source}")
    message(FATAL_ERROR "No-op source UB fix in ${path}")
  endif()
  file(WRITE "${path}" "${_patched}")
endfunction()

# bn_add() carry is represented by signed int 'c'. Shifting 1 << 31
# in the signed type is undefined behavior even when assigned to uint32_t.
# Convert only that final carry bit to uint32_t before shifting; other
# limb-array terms are already uint32_t expressions.
crypto_replace_exactly_once("${_gmssl}/src/secp256r1.c"
  "((c & 1) << 31)"
  "(((uint32_t)c & 1u) << 31)")
crypto_replace_exactly_once("${_gmssl}/src/secp384r1.c"
  "((c & 1) << 31)"
  "(((uint32_t)c & 1u) << 31)")

# The parsed ServerHello may contain an empty Session ID: the GmSSL parser
# then legitimately yields NULL with len=0. Calling memcpy(dst,NULL,0)
# violates the compiler's nonnull contract. Reject oversized/invalid nonzero
# spans and copy only when a source buffer is admitted.
crypto_replace_exactly_once("${_gmssl}/src/tls12.c"
[==[
	// session_id
	memcpy(conn->session_id, session_id, session_id_len);
	conn->session_id_len = session_id_len;
]==]
[==[
	// session_id
	if (session_id_len > sizeof(conn->session_id)
		|| (session_id_len && !session_id)) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (session_id_len) {
		memcpy(conn->session_id, session_id, session_id_len);
	}
	conn->session_id_len = session_id_len;
]==])

if(DEFINED GMSSL_UB_PATCH_REPORT)
  get_filename_component(_report_dir "${GMSSL_UB_PATCH_REPORT}" DIRECTORY)
  file(MAKE_DIRECTORY "${_report_dir}")
  file(SHA256 "${_gmssl}/src/secp256r1.c" _p256)
  file(SHA256 "${_gmssl}/src/secp384r1.c" _p384)
  file(SHA256 "${_gmssl}/src/tls12.c" _tls12)
  file(WRITE "${GMSSL_UB_PATCH_REPORT}"
    "{\n"
    "  \"classification\": \"CRYPTO_CANDIDATE_3_SOURCE_UB_FIXES_NOT_VCPKG_RELEASE\",\n"
    "  \"source_ub_fixes\": 3,\n"
    "  \"secp256r1_sha256\": \"${_p256}\",\n"
    "  \"secp384r1_sha256\": \"${_p384}\",\n"
    "  \"tls12_sha256\": \"${_tls12}\"\n"
    "}\n")
endif()
message(STATUS "Crypto GmSSL candidate: fixed signed carry shift in P-256/P-384 and NULL memcpy in TLS 1.2")
