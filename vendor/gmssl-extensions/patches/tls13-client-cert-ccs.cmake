# SPDX-License-Identifier: Apache-2.0
# Crypto #42: RFC 8446 appendix D.4 compatibility CCS at the TLS1.3
# SERVER'S first encrypted-client-Certificate boundary (normal handshake).
#
# Python ssl TLS1.3 middlebox mode sends one plaintext dummy CCS (type 20,
# version 0x0303, exactly one 0x01 byte) directly before the encrypted
# client Certificate, CertificateVerify and Finished flight. Pinned GmSSL
# 3.2.0#14 previously admitted this same CCS after HRR/ClientHello2 only
# and rejected this valid normal-handshake order with unexpected_message.
#
# Reuse THE SAME pinned private crypto_hrr_ccs_seen flag. No additional
# session state, no permissive retry, no plaintext-mac/Finished bypass.
# The CCS is NOT hashed into the TLS1.3 transcript or advances AEAD seq.
# A duplicate/malformed CCS or a CCS with acceptance disabled fails closed.
#
# This source-only test overlay must not change production GmSSL 3.2.0#14.
if(NOT COMMAND gmssl_replace_once)
    message(FATAL_ERROR "Pinned GmSSL source adaptation engine is required")
endif()
if(NOT DEFINED SOURCE_PATH OR NOT EXISTS "${SOURCE_PATH}/src/tls13.c")
    message(FATAL_ERROR "Pinned GmSSL TLS1.3 source must exist")
endif()
set(_mtls_tls13 "${SOURCE_PATH}/src/tls13.c")
gmssl_replace_once(
    "${_mtls_tls13}"
[==[
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if(conn->verbose) tls_trace("recv client {Certificate*}\n");
]==]
[==[
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	/* RFC 8446 D.4: an exact dummy CCS MAY precede encrypted client
	 * authentication records. Consume ONCE for this TLS1.3 association,
	 * using the same gate shared with HRR's ClientHello2 admission.
	 * Never change transcript, key schedule or record sequence on CCS.
	 */
	if (tls_record_type(conn->record) == TLS_record_change_cipher_spec) {
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
	if(conn->verbose) tls_trace("recv client {Certificate*}\n");
]==]
)
unset(_mtls_tls13)
