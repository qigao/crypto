# Crypto-owned post-import hardening. Do not edit the frozen 92 imported source
# blobs or change the 40 attested GmSSL 3.2.0#13 original transformations.
# All substitutions fail closed on source drift or ambiguous anchors.

function(crypto_gmssl_harden_once filename original fixed)
  if(NOT EXISTS "${filename}" OR "${original}" STREQUAL "")
    message(FATAL_ERROR "Invalid crypto source-hardening input: ${filename}")
  endif()
  file(READ "${filename}" _before)
  string(FIND "${_before}" "${original}" _at)
  if(_at EQUAL -1)
    message(FATAL_ERROR "Missing exact Crypto hardening anchor: ${filename}")
  endif()
  string(LENGTH "${original}" _length)
  math(EXPR _after_offset "${_at} + ${_length}")
  string(SUBSTRING "${_before}" ${_after_offset} -1 _remainder)
  string(FIND "${_remainder}" "${original}" _duplicate)
  if(NOT _duplicate EQUAL -1)
    message(FATAL_ERROR "Ambiguous Crypto hardening anchor: ${filename}")
  endif()
  string(REPLACE "${original}" "${fixed}" _after "${_before}")
  if("${_after}" STREQUAL "${_before}")
    message(FATAL_ERROR "Crypto hardening produced no source edit: ${filename}")
  endif()
  file(WRITE "${filename}" "${_after}")
endfunction()

# bn_add() returns an int carry bit. Signed (c & 1) << 31 has undefined
# behavior when c == 1. Cast the bit to a uint32_t before shifting to the
# high bit of the unsigned limb; the mathematical field operation is unchanged.
crypto_gmssl_harden_once(
  "${SOURCE_PATH}/src/secp256r1.c"
  [==[r[7] = (r[7] >> 1) | ((c & 1) << 31);]==]
  [==[r[7] = (r[7] >> 1) | ((uint32_t)(c & 1) << 31);]==])

crypto_gmssl_harden_once(
  "${SOURCE_PATH}/src/secp384r1.c"
  [==[r[11] = (r[11] >> 1) | ((c & 1) << 31);]==]
  [==[r[11] = (r[11] >> 1) | ((uint32_t)(c & 1) << 31);]==])

# TLS 1.2 ServerHello may contain a zero-length legacy session ID. The
# decoder's data pointer may legitimately be NULL for the empty vector.
# Never pass NULL to memcpy (even with size 0); also reject oversized IDs
# before copying to conn->session_id[32].
crypto_gmssl_harden_once(
  "${SOURCE_PATH}/src/tls12.c"
  [==[	// session_id
	memcpy(conn->session_id, session_id, session_id_len);
	conn->session_id_len = session_id_len;]==]
  [==[	// session_id
	if (session_id_len > sizeof(conn->session_id)
		|| (session_id_len && !session_id)) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (session_id_len) {
		memcpy(conn->session_id, session_id, session_id_len);
	}
	conn->session_id_len = session_id_len;]==])

message(STATUS "Applied 3 Crypto-owned post-import UB hardening edits")
