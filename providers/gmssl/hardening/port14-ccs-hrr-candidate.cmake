# Strict opt-in source integration candidate. Frozen original 92 source Git blobs
# are never edited. Only the PRIVATE verified, patched GmSSL source checkout
# is modified; installed Crypto ABI, target name and archive shape stay fixed.
if(NOT GMSSL_PORT14_CRYPTO_CANDIDATE)
  message(FATAL_ERROR "Source hardening candidate must be explicitly enabled")
endif()
set(_src "${SOURCE_PATH}/src")
set(_staged "${_crypto_root}/providers/gmssl/candidates/port14")
foreach(_header IN ITEMS tls13-compat-ccs.h tls13-hrr-padding.h)
  if(NOT EXISTS "${_staged}/${_header}")
    message(FATAL_ERROR "Missing immutable port14 candidate header: ${_header}")
  endif()
  configure_file("${_staged}/${_header}" "${_src}/${_header}" COPYONLY)
endforeach()
# Private compiled-source includes are early enough for both the first
# ClientHello retry reader and later encrypted handshake functions.
crypto_gmssl_harden_once(
  "${_src}/tls13.c"
  [==[#include <gmssl/tls.h>]==]
  [==[#include <gmssl/tls.h>
#include "tls13-compat-ccs.h"
#include "tls13-hrr-padding.h"]==])

# After baseline HRR hardening, redirect its inline parser to the single
# bounded shared CCS verifier used by the encrypted handshake reader.
crypto_gmssl_harden_once(
  "${SOURCE_PATH}/src/tls13.c"
  [==[	if (tls_record_type(conn->record) == TLS_record_change_cipher_spec) {
		if (!conn->ctx->accept_change_cipher_spec
			|| conn->crypto_hrr_ccs_seen != 0u) {
			tls13_send_alert(conn, TLS_alert_unexpected_message);
			return -1;
		}
		if (conn->recordlen != TLS_RECORD_HEADER_SIZE + 1u
			|| tls_record_protocol(conn->record) != TLS_protocol_tls12
			|| tls_record_get_change_cipher_spec(conn->record) != 1) {
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		conn->crypto_hrr_ccs_seen = 1u;
		tls_clean_record(conn);
		return TLS_ERROR_RECV_AGAIN;
	}
]==]
  [==[	if (tls_record_type(conn->record) == TLS_record_change_cipher_spec) {
		int admitted;
		if (!conn->ctx->accept_change_cipher_spec) {
			tls13_send_alert(conn, TLS_alert_unexpected_message);
			return -1;
		}
		/* Reuse the one TLS_CONNECT CCS budget across HRR and encrypted
		 * handshake; never add CCS to transcript or traffic counters. */
		admitted = gmssl_tls13_compat_ccs_admit(
			conn->record, conn->recordlen,
			conn->handshake_fragment_len - conn->handshake_fragment_offset,
			conn->handshake_message_len, &conn->crypto_hrr_ccs_seen);
		if (admitted != 1) {
			tls13_send_alert(conn, TLS_alert_unexpected_message);
			return -1;
		}
		tls_clean_record(conn);
		return TLS_ERROR_RECV_AGAIN;
	}
]==])

# Stage precisely the candidate encrypted handshake reader, reusing the
# preexisting single TLS_CONNECT private CCS field. No second counter.
file(READ "${_staged}/tls13-handshake-reader.h" _reader)
string(FIND "${_reader}" "handshake_compat_ccs_count" _legacy)
if(_legacy LESS 0)
  message(FATAL_ERROR "Missing candidate counter field")
endif()
string(REPLACE "handshake_compat_ccs_count" "crypto_hrr_ccs_seen" _reader "${_reader}")
# Fail closed if an already-consumed shared CCS budget or a pending handshake
# fragment is incorrectly allowed to consume another record.
string(FIND "${_reader}" "gmssl_tls13_compat_ccs_admit(" _parser)
if(_parser LESS 0)
  message(FATAL_ERROR "Candidate encrypted handshake reader has no bounded CCS parser")
endif()
file(WRITE "${_src}/tls13-handshake-reader.h" "${_reader}")
unset(_reader)
unset(_legacy)
unset(_parser)
# Candidate-only Crypto-owned RFC8446 CH2 padding admission; no old port ABI.
set(_gmssl_tls13 "${SOURCE_PATH}/src/tls13.c")
# RFC 8446 section 4.1.2 specifically permits adding, removing, or
# changing the length of ClientHello padding on retry. OpenSSL's default
# X25519-first HRR often adds a zero-filled padding extension to CH2.
# Do not weaken checks for any other extension, nor duplicate-extension
# rejection. Both CH1 and CH2 padding must contain only zero octets.
crypto_gmssl_harden_once("${_gmssl_tls13}"
[==[
		if (!matching_ext_found) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
]==]
[==[
		if (!matching_ext_found && ext_type != TLS_extension_padding) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
]==])

crypto_gmssl_harden_once("${_gmssl_tls13}"
[==[
		// check ext_data
		switch (ext_type) {
		case TLS_extension_key_share:
]==]
[==[
		/* RFC8446 4.1.2: second ClientHello padding may be new,
		 * omitted or resized. RFC7685 still requires all zero bytes. */
		if (ext_type == TLS_extension_padding) {
			if (!gmssl_tls13_hrr_padding_valid(ext_data, ext_datalen)) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			continue;
		}
		// check ext_data
		switch (ext_type) {
		case TLS_extension_key_share:
]==])

crypto_gmssl_harden_once("${_gmssl_tls13}"
[==[
		if (_ext_type == TLS_extension_early_data) {
			continue;
		}
		if (_ext_type == TLS_extension_key_share && key_share) {
]==]
[==[
		if (_ext_type == TLS_extension_early_data) {
			continue;
		}
		if (_ext_type == TLS_extension_padding) {
			/* CH1 padding can disappear on HRR. Reject nonzero padding
			 * even when the second ClientHello omits this extension. */
			if (!gmssl_tls13_hrr_padding_valid(_ext_data, _ext_datalen)) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			continue;
		}
		if (_ext_type == TLS_extension_key_share && key_share) {
]==])



unset(_gmssl_tls13)

message(STATUS "Crypto candidate: single CCS budget for HRR and encrypted TLS1.3 + zero-only CH2 padding")
